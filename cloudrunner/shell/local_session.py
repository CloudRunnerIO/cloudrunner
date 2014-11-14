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

import msgpack
import logging
from socket import gethostbyname
from threading import Thread
import time
import zmq
import uuid

from cloudrunner.core import parser
from cloudrunner.core.exceptions import ConnectionError
from cloudrunner.core.message import (M, StatusCodes, LocalJobRep,
                                      PipeMessage, FinishedMessage)

LOG = logging.getLogger('LocalSession')


class Session(Thread):

    def __init__(self, ctx, worker_sock_uri, repl_uri, msg, run_event,
                 timeout=None, host_resolver=None, **kwargs):
        self.session_id = uuid.uuid4().hex
        self.worker_sock = ctx.socket(zmq.DEALER)
        self.worker_sock.setsockopt(zmq.IDENTITY, self.session_id)
        self.worker_sock.connect(worker_sock_uri)
        self.context = ctx
        self.kwargs = kwargs
        self.run_event = run_event
        self.ctx = ctx
        self.reply_sock = ctx.socket(zmq.DEALER)
        self.reply_sock.connect(repl_uri)
        self.host_resolver = host_resolver

        super(Session, self).__init__()

        self.message = M.build(msg)
        task = self.message.tasks[0]
        self.sections = parser.split_sections(task['script'])
        if not self.sections:
            raise Exception("Invalid request, no executable sections found")
        self.steps = []
        self.timeout = task["timeout"] or 10

        local_run = self.sections.pop(0)

        if local_run.strip():
            self.local_script = local_run
        else:
            self.local_script = ''

        for i in range(0, len(self.sections), 2):
            targets, section = self.sections[i], self.sections[i + 1]
            target_str = parser.parse_selectors(targets)[0]
            targets = target_str.split()

            self.steps.append((target_str, targets, section,
                               kwargs.get("includes")))

    def run(self):

        if self.local_script:
            # run local script
            pass

        env = self.kwargs.pop('env', {})
        ret = []

        new_env = {}
        try:
            for step in self.steps:
                job_id, msg_ret = self.execute_step(env, *step)

                for _ret in msg_ret:
                    _env = _ret['env']
                    for k, v in _env.items():
                        if k in new_env:
                            if not isinstance(new_env[k], list):
                                new_env[k] = [new_env[k]]
                            if isinstance(v, list):
                                new_env[k].extend(v)
                            else:
                                new_env[k].append(v)
                        else:
                            new_env[k] = v

                env.update(new_env)

                ret.append(dict(targets=step[0],
                                jobid=job_id,
                                response=msg_ret))
            response = []
            for run in ret:
                nodes = run['response']
                exec_result = [dict(
                    node=node['node'], run_as=node['remote_user'],
                    ret_code=node['ret_code']) for node in nodes]
                response.append(dict(targets=run['targets'],
                                     jobid=run['jobid'],
                                     nodes=exec_result))

            fin_msg = FinishedMessage(
                session_id=self.session_id,
                user='',
                org='',
                response=response,
            )

            try:
                self.reply_sock.send_multipart(
                    fin_msg.pack(self.session_id, self.session_id))
            except:
                pass
        finally:
            self.close()

    def execute_step(self, env, targets, targets_uris, script, libs):
        # 2 sec default
        job_id = uuid.uuid4().hex
        start_time = time.time()
        end_discovery_time = start_time + 3
        node_map = {}

        hosts = []
        for target in targets_uris:
            try:
                host = gethostbyname(target)
                hosts.append((target, host))
            except Exception, ex:
                # Try the resolvehost.conf file
                if self.host_resolver and target in self.host_resolver:
                    _hosts = self.host_resolver[target]
                    for host in _hosts:
                        hosts.append((target, host))
                else:
                    LOG.warn("Cannot resolve hostname: %s" % target)
                    continue

        try:
            num_nodes = 0

            request = dict(env=env, script=script,
                           libs=libs)
            for (tgt, host) in hosts:
                self.worker_sock.send_multipart(
                    [tgt, host, 'REQ', self.session_id, tgt])

            # while end_time - time.time() > 0:
                # if self.worker_sock.poll(100):
                #    num_nodes += 1
                #    frames = self.worker_sock.recv_multipart()
            end_time = time.time() + self.timeout
            while not self.run_event.is_set() and end_time - time.time() > 0:
                if not self.worker_sock.poll(400):
                    if time.time() - end_discovery_time > 0 and num_nodes <= 0:
                        break
                    else:
                        continue

                frames = self.worker_sock.recv_multipart()
                if frames[0] != self.session_id:
                    # Skip
                    continue
                if len(frames) == 3:
                    # Ready
                    num_nodes += 1
                    tgt = frames[0]
                    for (tgt, host) in hosts:
                        self.worker_sock.send_multipart([
                            tgt, host, 'REQ', self.session_id,
                            "JOB", msgpack.packb(['@', request])])
                    continue
                # else:
                #    self.reply_sock.send_multipart(list(frames))
                job_rep = LocalJobRep.build(*frames)
                state = node_map.setdefault(
                    job_rep.peer,
                    dict(
                        status=StatusCodes.STARTED,
                        data={},
                        remote_user=job_rep.run_as,
                        stdout='',
                        stderr=''))
                if job_rep.data:
                    state['data'].update(job_rep.data)

                if job_rep.control == StatusCodes.FINISHED:
                    # frames[4]
                    num_nodes -= 1
                    node_map[job_rep.peer]['status'] = StatusCodes.FINISHED
                elif job_rep.control in [StatusCodes.STDOUT,
                                         StatusCodes.STDERR]:
                    pipe_msg = PipeMessage(
                        session_id=self.session_id,
                        task_name='',
                        user=job_rep.run_as,
                        org='',
                        targets=targets,
                        tags='',
                        job_id=job_rep.job_id,
                        run_as=job_rep.run_as,
                        node=job_rep.peer,
                        stdout=job_rep.data.get('stdout', ''),
                        stderr=job_rep.data.get('stderr', '')
                    )
                    self.reply_sock.send_multipart(
                        pipe_msg.pack(self.session_id, self.session_id))

                else:
                    # node_map[peer][stdout] =
                    outputs = msgpack.unpackb(frames[4])
                    outputs.setdefault('stdout', "")
                    outputs.setdefault('stderr', "")

                    pipe_msg = PipeMessage(
                        session_id=self.session_id,
                        user=job_rep.run_as,
                        org='',
                        job_id=job_rep.job_id,
                        run_as=job_rep.run_as,
                        node=job_rep.peer,
                        stdout=outputs['stdout'],
                        stderr=outputs['stderr']
                    )
                    self.reply_sock.send_multipart(
                        pipe_msg.pack(self.session_id))
        except zmq.ZMQError, zerr:
            if not self.run_event.is_set():
                if (self.ctx.closed or zerr.errno == zmq.ETERM or
                        zerr.errno == zmq.ENOTSUP or
                        zerr.errno == zmq.ENOTSOCK):
                    # System interrupt
                    raise ConnectionError()
        except Exception, ex:
            LOG.exception(ex)

        return job_id, [dict(node=k,
                             remote_user=n['remote_user'],
                             job_id=job_id,
                             env=n['data'].get('env', {}),
                             stdout=n['data'].get('stdout', ''),
                             stderr=n['data'].get('stderr', ''),
                             ret_code=n['data'].get('ret_code', -255))
                        for k, n in node_map.items()]

    def close(self):
        self.worker_sock.close()
        self.reply_sock.close()
