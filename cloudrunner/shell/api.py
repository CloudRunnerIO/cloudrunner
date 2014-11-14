#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 CloudRunner.IO
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import msgpack
import os
import sys
from cloudrunner.core import message, parser
from cloudrunner.util.loader import local_plugin_loader, load_plugins
from cloudrunner.plugins.state.base import StatePluginBase


LOG = logging.getLogger(__name__)


class AsyncResp(object):

    def __init__(self, caller, queue):
        self.queue = queue
        self.env = {}
        self.ready = False
        self.caller = caller

    def iter(self, timeout=5):
        while not self.ready:
            try:
                frames = self.queue.recv(timeout)
                if frames:
                    msg = None
                    try:
                        msg = message.TransportMessage.unpack(*frames)
                        LOG.debug("Received message: %s", vars(msg))
                    except:
                        LOG.error("Received frames: %r", frames)
                    if msg:
                        yield msg
                    else:
                        LOG.error("Received frames: %r", frames)
                    if msg and msg.status == message.StatusCodes.FINISHED:
                        break
                else:
                    yield "Empty/wrong response from server"
                    return
            except Exception, ex:
                LOG.exception(ex)
                yield str(ex)
                return

    def __iter__(self):
        return self.iter()


class AsyncRespLocal(object):

    def __init__(self, caller, run_wrap):
        self.run_wrap = run_wrap
        self.env = caller.env or {}
        self.caller = caller

    def iter(self, timeout=5):
        proc_iter = iter(self.run_wrap)
        proc = next(proc_iter)
        if not isinstance(proc, list):
            while True:
                try:
                    to_read = proc.select(.2)
                    if proc.poll() is not None:
                        # We are done with the task
                        break
                    for fd_type in to_read:
                        proc_stdout, proc_stderr = '', ''

                        if fd_type == proc.STDOUT:
                            proc_stdout = proc.read_out()

                        if fd_type == proc.STDERR:
                            proc_stderr = proc.read_err()

                        yield message.PipeMessage(
                            session_id="",
                            step_id=1,
                            user=proc.run_as,
                            org='',
                            job_id='local',
                            run_as=proc.run_as,
                            node='localhost',
                            stdout=proc_stdout,
                            stderr=proc_stderr,
                        )
                except KeyboardInterrupt:
                    break
            run_as, ret_code, stdout, stderr, env = next(proc_iter)
        else:
            run_as, ret_code, stdout, stderr, env = proc

        self.env = env
        self.caller.env.update(env)


class CloudRunner(object):
    DEFAULT_TIMEOUT = 60

    default_transport = 'cloudrunner.plugins.transport.' \
        'rest_transport.RESTTransport'
    plugins = {}

    def __init__(self, transport, plugins=None,
                 request_timeout=DEFAULT_TIMEOUT,
                 auth_user=None, auth_token=None, **kwargs):
        self.transport = transport
        self.plugins = plugins
        self.request_timeout = request_timeout
        self.env = {}
        self.auth_user = auth_user
        self.auth_token = auth_token
        self._queue = None
        self.transport.prepare()

    @classmethod
    def from_config(cls, config, **kwargs):
        transport_str = config.transport_class or cls.default_transport
        transport_class = local_plugin_loader(transport_str)
        transport = transport_class.from_config(config, **kwargs)
        plugins = load_plugins(config)
        if not plugins:
            # load defaults
            from cloudrunner.util.loader import load_plugins_from
            load_plugins_from('cloudrunner.plugins.state.functions',
                              [StatePluginBase])

        return cls(transport=transport, plugins=plugins, **kwargs)

    @property
    def queue(self):
        if self._queue is None:
            self._queue = self.transport.publish_queue('requests')
        return self._queue

    def set_env(self, env):
        self.env = env

    def close(self, force=True):
        self.transport.terminate(force=True)

    def terminate(self, session_id, sig="term", to_read=True):
        req = message.Term()
        req.dest = session_id
        req.signal = sig
        req.reason = 'CLI:Stop'

        self.queue.send(*req.pack(), **req.kwargs)

        if not to_read:
            return

        r = self.queue.recv(timeout=5)
        status, resp = r

        if len(r) != 2:
            raise Exception('Error: {}'.format(r[0]))

        return msgpack.unpackb(resp)

    def run_local(self, script_content):
        from cloudrunner.core.process import Processor

        if os.name != 'nt':
            import pwd

            run_as = pwd.getpwuid(os.getuid())[0]
        else:
            import win32api
            import win32con

            run_as = win32api.GetUserNameEx(win32con.NameSamCompatible)

        proc = Processor(run_as)
        lang = parser.parse_lang(script_content)
        wrap = proc.run(script_content, lang, self.env)
        return AsyncRespLocal(self, wrap)

    def run_remote(self, script_content, includes=None, tags=None,
                   caller=None, test=False):
        req = message.Dispatch(user='', roles={'*': '@'}, tasks=[],
                               env=self.env)
        task = {}

        if includes:
            task['includes'] = includes

        task['script'] = script_content

        task["timeout"] = self.request_timeout

        req.tasks.append(task)

        self.queue.send(req.pack())
        return AsyncResp(self, self.queue)
