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
import json
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
            msg = self.get_message(timeout=timeout)
            if msg:
                LOG.debug("Received message: %s", msg.status)
            if msg and msg.status == message.StatusCodes.FINISHED:
                self.ready = True
            if msg:
                yield msg

    def get_message(self, timeout=None):
        frames = self.queue.recv(timeout)
        LOG.debug("Received frames: %r", frames)
        if frames:
            return message.TransportMessage.unpack(*frames)


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
                            task_name="",
                            user=proc.run_as,
                            org='',
                            targets="local",
                            tags='',
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
        'zmq_transport.ZmqCliTransport'
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

    def build_request(self):
        _req = message.AgentReq(login=self.auth_user,
                                password=self.auth_token)
        return _req

    def close(self, force=True):
        self.transport.terminate(force=True)

    def notify(self, session_id=None, job_id=None, data=None, targets=None,
               to_read=True):
        req = self.build_request()
        req.append(control='notify')

        req.append(data=data)
        req.append(targets=targets)
        req.append(session_id=session_id)
        req.append(job_id=job_id)

        self.queue.send(*req.pack())

        if not to_read:
            return

        resp = self.queue.recv(timeout=5)

        if not resp:
            raise Exception("Cannot connect to server")

        status, r = resp

        if len(r) != 2:
            raise Exception('Error: {}'.format(r[0]))
        return r[1]

    def terminate(self, session_id, sig="term", to_read=True):
        req = self.build_request()
        req.append(control='term')

        req.append(session_id=session_id)
        req.append(action=sig)

        self.queue.send(*req.pack())

        if not to_read:
            return

        r = self.queue.recv(timeout=5)
        status, resp = r

        if len(r) != 2:
            raise Exception('Error: {}'.format(r[0]))

        return json.loads(resp)

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
        req = self.build_request()
        req.append(control='dispatch')

        if includes:
            req.append(includes=includes)

        if tags:
            req.append(tags=tags)

        if caller:
            req.append(caller=caller)

        if test:
            req.append(test=True)

        req.append(data=script_content)

        if self.env:
            req.append(env=self.env)

        req.append(timeout=self.request_timeout)

        self.queue.send(*req.pack())
        return AsyncResp(self, self.queue)

    def attach(self, session_id, targets):
        req = self.build_request()
        req.append(control='attach')

        req.append(session_id=session_id)
        req.append(data=json.dumps(targets))

        # we do not know the original timeout,
        self.timeout = sys.maxint / 1000

        self.queue.send(*req.pack())
        r = self.queue.recv(timeout=5)
        status, resp = r

        if len(r) != 2:
            raise Exception('Error: {}'.format(r[0]))

        return status, resp

    def _list_nodes_get(self, command):
        req = self.build_request()
        req.append(control=command)

        self.queue.send(*req.pack())
        status, resp = self.queue.recv(timeout=5)
        if status == "ERR":
            raise Exception("Error getting nodes on Master: {}".format(resp))

        result = json.loads(resp)
        if not result[0]:
            raise Exception("Error getting nodes on Master: {}".format(result))
        return result[1]

    def list_active_nodes(self):
        return self._list_nodes_get('list_active_nodes')

    def list_nodes(self):
        return self._list_nodes_get('list_nodes')

    def list_pending_nodes(self):
        return self._list_nodes_get('list_pending_nodes')

    @property
    def library(self):
        if hasattr(self, "_library"):
            return self._library
        _library = {}

        if self.transport.mode != "server":
            return _library

        try:
            success, result = self.get_plugin("library",
                                              args=["list", "--json"])[0]
            if success:
                for store_name, items in result.items():
                    for item in items:
                        item_name = "[%s]://%s" % (store_name, item['name'])
                        item_path = item['name']
                        _library[item_name] = item_path
                self._library = _library
        except:
            pass

        return _library

    def get_plugin(self, controller, data=None, args=None):
        req = self.build_request()
        req.append(plugin=controller)
        req.append(control='plugin', data=data)
        req.append(args='"' + '" "'.join(args) + '"')

        self.queue.send(*req.pack())
        resp = self.queue.recv()
        if len(resp) > 1:
            return json.loads(resp[1])
        else:
            return {}

    def list_plugins(self):
        req = self.build_request()
        req.append(control='plugins')

        self.queue.send(*req.pack())
        success, result = self.queue.recv()
        if success and len(result) > 0:
            return json.loads(result)
        else:
            return []
