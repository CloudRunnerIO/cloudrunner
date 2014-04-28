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
import abc

import json
import time

from cloudrunner.util.string import stringify1

# Requests

TOKEN_SEPARATOR = '~~~~~'
ADMIN_TOWER = 'cloudrunner-control'
HEARTBEAT = 'cloudrunner-heartbeat'
DEFAULT_ORG = 'DEFAULT'


class StatusCodes(object):
    READY = 'READY'
    STARTED = 'STARTED'
    WORKING = 'WORKING'
    PIPEOUT = 'PIPEOUT'
    STDOUT = 'STDOUT'
    STDERR = 'STDERR'
    FINISHED = 'FINISHED'
    EVENTS = 'EVENTS'
    HB = 'HB'
    WELCOME = 'WELCOME'
    RELOAD = 'RELOAD'

    @staticmethod
    def pending():
        return ['READY', 'STARTED', 'WORKING',
                'PIPEOUT', 'EVENTS', 'STDOUT', 'STDERR']

    @staticmethod
    def pipes():
        return ['PIPEOUT', 'STDOUT', 'STDERR']


def is_valid_host(host):
    if not host:
        return False
    return not filter(lambda x: x.lower() == host.lower(),
                     (ADMIN_TOWER.lower(), HEARTBEAT.lower()))


class BaseMessage(object):

    def _str(self, value):
        if isinstance(value, unicode):
            return value.encode('utf8')
        else:
            return value

    def __str__(self):
        return str(vars(self).items())

    @classmethod
    def build(cls, *args):
        try:
            obj = cls(*args)
            return obj
        except Exception, ex:
            return False


class AgentReq(BaseMessage):

    def __init__(self, login=None, auth_type=1, password=None, control=None,
                 data=None, extra_json=None):
        self.login = self._str(login)
        self.password = self._str(password)
        #assert self.password
        self.auth_type = int(auth_type)
        self.control = self._str(control)
        if data:
            self.data = self._str(data)
        else:
            self.data = data
        self.kwargs = {}
        if extra_json:
            self.kwargs = json.loads(extra_json)

    def append(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, self._str(v))
            else:
                self.kwargs[k] = self._str(v)

    def pack(self):
        return [
            self.login, str(self.auth_type), self.password, self.control,
            self.data or '', json.dumps(self.kwargs)]


class ScheduleReq(BaseMessage):

    def __init__(self, control, job_id):
        self.control = self._str(control)
        self.job_id = self._str(job_id)

    def pack(self):
        return [self.control, self.job_id]


class HeartBeatReq(BaseMessage):

    """
    \x00k\x01, node_id, Org, ACTION
    """

    def __init__(self, ident, peer, org, control, *args):
        self.ident = ident
        self.peer = peer
        self.org = org
        self.control = control


class FwdReq(BaseMessage):

    """
    ident, json_packet
    """

    def __init__(self, ident, datagram, *args):
        self.ident = ident
        self.data = json.loads(datagram)


class ClientReq(BaseMessage):

    def __init__(self, ident, peer, org, datagram):
        self.ident = ident
        self.peer = peer
        self.org = org
        if datagram:
            try:
                data = json.loads(datagram)
            except ValueError:
                data = None
        if data:
            if len(data) > 1:
                self.dest = str(data[0])
                self.control = str(data[1])
                if len(data) > 2:
                    self.data = str(data[2])
                else:
                    self.data = None
                if len(data) > 3:
                    self.extra = str(data[3])
                else:
                    self.extra = None
            else:
                self.control = str(data[0])
                self.dest = None
                self.data = None
                self.extra = None
        else:
            self.dest = None
            self.control = None
            self.data = None
            self.extra = None


class RerouteReq(BaseMessage):

    def __init__(self, req):
        self.dest = req.dest
        self.ident = req.ident
        self.org = req.org
        self.peer = req.peer
        self.control = req.control
        self.data = req.data
        self.extra = req.extra

    def pack(self):
        packed = [str(self.dest), str(self.ident), self.peer or '',
                  str(self.org), str(self.control), self.data or '']
        if self.extra:
            packed.append(self.extra)

        return packed


class ControlReq(BaseMessage):

    def __init__(self, ident, peer, org, control, node, data=None, extra=None):
        self.ident = ident
        self.peer = peer
        self.org = org
        self.control = control
        self.node = node
        self.data = None
        self.extra = None
        if data:
            self.data = data
        if extra:
            self.extra = extra

# Replies


class RegisterRep(BaseMessage):

    def __init__(self, frames):
        self.reply = frames[0]
        if len(frames) >= 1:
            self.data = frames[1]
        else:
            self.data = ''


class ClientRep(BaseMessage):

    def __init__(self, ident, peer, dest, control, *args):
        self.ident = ident
        self.peer = peer
        self.dest = dest
        self.control = control
        if args:
            self.data = args[0]
            self.extra = args[1:]
        else:
            self.data = ''
            self.extra = None

    def pack(self):
        if self.extra:
            return [self.ident, json.dumps([self.dest, self.control,
                                            self.data, self.extra])]
        else:
            return [self.ident,
                    json.dumps([self.dest, self.control, self.data])]


class JobRep(BaseMessage):

    def __init__(self, ident, peer, org, control, run_as=None, data=None, *args):
        self.ident = ident
        self.peer = peer
        self.org = org
        self.control = control

        self.run_as = run_as
        try:
            self.data = json.loads(data)
        except:
            self.data = None
        if args:
            self.extra = list(args)


class LocalJobRep(BaseMessage):

    def __init__(self, job_id, peer, control, run_as=None, data=None, *args):
        self.job_id = job_id
        self.peer = peer
        self.control = control

        self.run_as = run_as
        try:
            self.data = json.loads(data)
        except:
            self.data = None
        if args:
            self.extra = list(args)


class JobInput(BaseMessage):

    def __init__(self, _, cmd, job_id, user, org,
                 data=None, targets=None, *args):
        self.cmd = cmd
        self.job_id = job_id
        self.user = user
        self.org = org
        self.data = data
        self.targets = targets


class TransportMessage(object):
    __metaclass__ = abc.ABCMeta

    pack_order = []
    unpack_functions = {}

    def default_packer(self, val):
        return stringify1(val)

    def pack(self, proxy, peer):
        # reply: 'PIPE', job_id, run_as, node_id, stdout, stderr
        # reply-fwd: session_id, PIPEOUT, session_id, time,
        #   task_name, user, targets, tags, job_id, run_as,
        #   node_id, stdout, stderr

        data = [self.status, str(int(time.time()))]
        for field_name in self.pack_order:
            val = getattr(self, field_name)
            packed_val = getattr(self, "pack_%s" % field_name,
                                 self.default_packer)(val)
            data.append(packed_val)

        return [proxy, peer] + [json.dumps(data)]

    @classmethod
    def unpack(cls, status, timestamp, *args):
        """ Build the proper message from frames+
        """
        target_klass = None

        for klass in cls.__subclasses__():
            if klass.status == status:
                target_klass = klass

        if target_klass is None:
            return None

        msg_kwargs = {}
        for idx, field_name in enumerate(target_klass.pack_order):
            val = args[idx]
            unpack_function = target_klass.unpack_functions.get(field_name,
                                                                lambda x: x)
            msg_kwargs[field_name] = unpack_function(val)

        return target_klass(**msg_kwargs)


class PipeMessage(TransportMessage):
    status = StatusCodes.PIPEOUT
    pack_order = ["session_id", "task_name", "user", "org", "targets",
                  "tags", "job_id", "run_as", "node", "stdout", "stderr"]

    def __init__(self, session_id, task_name, user, org, targets, tags,
                 job_id, run_as, node, stdout=None, stderr=None):
        self.session_id = session_id
        self.task_name = task_name
        self.user = user
        self.org = org
        self.targets = targets
        self.tags = tags
        self.job_id = job_id
        self.run_as = run_as
        self.node = node
        self.stdout = stdout
        self.stderr = stderr


class FinishedMessage(TransportMessage):
    status = StatusCodes.FINISHED
    pack_order = ["session_id", "task_name", "user", "org",
                  "tags", "script", "response"]

    unpack_functions = {
        "response": json.loads,
    }

    def __init__(self, session_id, task_name, user, org, tags,
                 script, response):
        self.session_id = session_id
        self.task_name = task_name
        self.user = user
        self.org = org
        self.tags = tags
        self.script = script
        self.response = response

    def pack_response(self, resp):
        return json.dumps(resp)
