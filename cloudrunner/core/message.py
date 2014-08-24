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
from collections import OrderedDict
import logging
import msgpack

from cloudrunner.util.string import stringify1

# Requests

TOKEN_SEPARATOR = '~~~~~'
ADMIN_TOWER = 'cloudrunner-control'
HEARTBEAT = 'cloudrunner-heartbeat'
DEFAULT_ORG = 'DEFAULT'
LOG = logging.getLogger()


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
    return not filter(lambda x: x.lower() == host.lower(), (
        ADMIN_TOWER.lower(), HEARTBEAT.lower()))


class MsgType(type):

    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'registry'):
            # this is the base class.  Create an empty registry
            cls.registry = {}
        else:
            # this is a derived class.  Add cls to the registry
            interface_id = name.upper()
            cls.registry[interface_id] = cls

        super(MsgType, cls).__init__(name, bases, dct)

    def __call__(cls, *args):
        values = list(args)
        if cls is M:
            # Generic call
            msg_name = values.pop(0).upper()
            cls = cls.registry[msg_name]
        LOG.info("Creating %s with [%s]" % (cls, values))
        obj = super(MsgType, cls).__call__()
        for i, field in enumerate(obj.fields):
            if i >= len(values):
                break
            if hasattr(obj, 'mod_' + field):
                v = getattr(obj, 'mod_' + field)(values[i])
            else:
                v = values[i]
            setattr(obj, field, v)
        return obj


class M(object):
    __metaclass__ = MsgType
    dest = ''

    def _str(self, value):
        if isinstance(value, unicode):
            return value.encode('utf8')
        else:
            return value

    def __str__(self):
        return str(vars(self).items())

    def __repr__(self):
        return str(vars(self))

    @property
    def control(self):
        return self.__class__.__name__.upper()

    def values(self, skip=[]):
        if skip:
            return [getattr(self, f, '') for f in self.fields if f not in skip]
        else:
            return [getattr(self, f, '') for f in self.fields]

    def pack(self, skip=[]):
        return msgpack.packb([self.control] + self.values(skip=skip))

    _ = property(pack)

    @classmethod
    def repack(cls, pack):
        args = pack.values
        try:
            obj = cls(*args)
            return obj
        except Exception, ex:
            LOG.warn(args)
            LOG.exception(ex)
            return False

    @classmethod
    def build(cls, *args):
        try:
            obj = cls(*args)
            return obj
        except Exception, ex:
            LOG.exception(ex)
            return False

    @classmethod
    def unpack(cls, pack):
        args = msgpack.unpackb(pack)
        return M.build(*args)


class Dispatch(M):

    dest = ''
    fields = ["user", "roles", "data", "libraries"]


class ScheduleReq(M):

    def __init__(self, control, job_id):
        self.control = self._str(control)
        self.job_id = self._str(job_id)

    def pack(self):
        return [self.control, self.job_id]


class HeartBeatReq(M):

    """
    \x00k\x01, node_id, Org, ACTION
    """

    def __init__(self, ident, peer, org, control, *args):
        self.ident = ident
        self.peer = peer
        self.org = org
        self.control = control


class FwdReq(M):

    """
    ident, data_packet
    """

    def __init__(self, ident, datagram, *args):
        self.ident = ident
        self.data = msgpack.packb(datagram)


class ClientReq(M):

    fields = ['ident', 'peer', 'org', 'data', 'extra']

    def mod_data(self, val):
        if val:
            self.data = msgpack.unpackb(val)
        return val

    mod_extra = mod_data


class RerouteReq(M):

    fields = ['dest', 'ident', 'org', 'peer', 'control', 'data', 'extra']


class ControlReq(M):

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


class Ident(M):

    dest = HEARTBEAT
    fields = []


class Welcome(M):

    dest = HEARTBEAT
    fields = []


class Reload(M):

    dest = HEARTBEAT
    fields = []


class HB(M):

    dest = HEARTBEAT
    fields = []


class HBR(M):

    dest = HEARTBEAT
    fields = ['node']


class Init(M):
    dest = 'INIT'
    fields = ['org_id', 'org_name', 'session_key', 'session_iv']


class Quit(M):
    dest = ''
    fields = []


class Term(M):
    fields = ['dest', 'reason']


class Input(M):
    fields = ['dest', 'cmd', 'data']


class Crypto(M):
    dest = ''
    fields = ['message']

# Replies


class RegisterRep(M):

    def __init__(self, frames):
        self.reply = frames[0]
        if len(frames) >= 1:
            self.data = frames[1]
        else:
            self.data = ''


class ClientRep(M):

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
            return [self.ident, msgpack.packb([self.dest, self.control,
                                               self.data, self.extra])]
        else:
            return [self.ident,
                    msgpack.packb([self.dest, self.control, self.data])]


class JobRep(M):
    fields = ['ident', 'peer', 'org', 'msg']

    @property
    def reply(self):
        return M.build(*msgpack.unpackb(self.msg))


class StdOut(M):
    fields = ['job_id', 'run_as', 'output']


class StdErr(M):
    fields = ['job_id', 'run_as', 'stderr']


class Finished(M):
    fields = ['run_as', 'stdout', 'stderr', 'env', 'ret_code']


class Events(M):
    fields = ['run_as', 'result']


class Job(M):
    fields = ['dest', 'remote_user', 'request']


class LocalJobRep(M):

    def __init__(self, job_id, peer, control, run_as=None, data=None, *args):
        self.job_id = job_id
        self.peer = peer
        self.control = control

        self.run_as = run_as
        try:
            self.data = msgpack.unpackb(data)
        except:
            self.data = None
        if args:
            self.extra = list(args)


class JobInput(M):

    def __init__(self, _, cmd, job_id, user, org,
                 data=None, targets=None, *args):
        self.cmd = cmd
        self.job_id = job_id
        self.user = user
        self.org = org
        self.data = data
        self.targets = targets


# Node

class Ready(M):
    run_as = ''
    fields = ['dest', 'status']

# Frames


class Frame(object):

    def __init__(self, ident, peer, org, msg):
        self.ident = ident
        self.peer = peer
        self.org = org
        self.msg = msg

    def __repr__(self):
        return str(vars(self))

    @property
    def message(self):
        if not hasattr(self, '_m'):
            try:
                self._m = M.build(*msgpack.unpackb(self.msg))
            except Exception, ex:
                print ex
                return None
        return self._m

    @property
    def _(self):
        return [self.ident, self.peer, self.org, self.msg]

    def reroute(self):
        if not self.message:
            raise Exception("Frame message is None")
        return [self.message.dest, self.ident, self.peer, self.org, self.msg]

    def reply(self, msg):
        return [self.ident, msg._]

F = Frame


class ReplyFrame(object):

    def __init__(self, ident, msg):
        self.ident = ident
        self.msg = msg

    def __repr__(self):
        return str(vars(self))

    @property
    def message(self):
        if not hasattr(self, '_m'):
            try:
                self._m = M.build(*msgpack.unpackb(self.msg))
            except Exception, ex:
                print ex
                return None
        return self._m

    @property
    def _(self):
        return [self.ident, self.msg]

R = ReplyFrame


class RouterFrame(object):

    def __init__(self, *args):
        _m = M.build(*args)
        self.dest = _m.dest
        self.msg = _m.pack()

    def __repr__(self):
        return str(vars(self))

    @property
    def _(self):
        return [self.dest, self.msg]

RT = RouterFrame

# Transport


class TransportMessage(object):
    __metaclass__ = abc.ABCMeta

    pack_order = []
    unpack_functions = {}
    _seq_no = 0

    def default_packer(self, val):
        return stringify1(val)

    def pack(self):
        # reply: 'PIPE', job_id, run_as, node_id, stdout, stderr
        # reply-fwd: session_id, PIPEOUT, session_id, time,
        #   task_name, user, targets, tags, job_id, run_as,
        #   node_id, stdout, stderr

        return dict([(k, getattr(self, k, None)) for k in self.pack_order])

    @property
    def seq_no(self):
        return self._seq_no

    @seq_no.setter
    def seq_no(self, seq_no):
        self._seq_no = seq_no

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

        inst = target_klass()
        for idx, field_name in enumerate(target_klass.pack_order):
            val = args[idx]
            unpack_function = target_klass.unpack_functions.get(field_name,
                                                                lambda x: x)
            setattr(inst, field_name, unpack_function(val))

        return inst


class InitialMessage(TransportMessage):
    status = StatusCodes.STARTED
    pack_order = ["type", "session_id",
                  "ts", "org", "seq_no", "step_id"]

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if k in self.pack_order:
                setattr(self, k, v)
        self.type = "INITIAL"


class PipeMessage(TransportMessage):
    status = StatusCodes.PIPEOUT
    pack_order = ["type", "session_id", "ts", "seq_no", "org", "step_id",
                  "user", "job_id", "run_as", "node", "stdout", "stderr"]

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if k in self.pack_order:
                setattr(self, k, v)
        self.type = "PARTIAL"


class FinishedMessage(TransportMessage):
    status = StatusCodes.FINISHED
    pack_order = ["type", "session_id", "ts", "seq_no",
                  "user", "org", "step_id", "result"]

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if k in self.pack_order:
                setattr(self, k, v)
        self.type = "FINISHED"
