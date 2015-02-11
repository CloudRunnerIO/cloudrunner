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

# Requests

TOKEN_SEPARATOR = '~~~~~'
ADMIN_TOWER = '_CTRL'
HEARTBEAT = '_HB'
LOG = logging.getLogger('CR MSG')

LOG.setLevel(logging.ERROR)


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


class DictWrapper(dict):

    def __getattr__(self, item):
        if item in self.keys():
            return self[item]
        else:
            raise IndexError(item)

    def __setattr__(self, item, value):
        self[item] = value


class SafeDictWrapper(dict):

    def __getattr__(self, item):
        if item in self.keys():
            return self[item]
        else:
            return ''

    def __setattr__(self, item, value):
        self[item] = value


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

    def __call__(cls, *args, **kwargs):
        values = list(args)
        if cls is M:
            # Generic call
            msg_name = kwargs.get('c')
            if not msg_name:
                msg_name = values.pop(0)
            msg_name = msg_name.upper()
            cls = cls.registry[msg_name]
        obj = super(MsgType, cls).__call__()
        obj.kw = []
        obj.hdr = SafeDictWrapper()

        for i, field in enumerate(obj.fields):
            if i >= len(values):
                break
            if hasattr(obj, 'mod_' + field):
                v = getattr(obj, 'mod_' + field)(values[i])
            else:
                v = values[i]
            setattr(obj, field, v)
        for field, value in kwargs.items():
            obj.kw.append(field)
            if hasattr(obj, 'mod_' + field):
                v = getattr(obj, 'mod_' + field)(value)
            else:
                v = value
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

    def values(self):
        d = dict((f, getattr(self, f, ''))
                 for f in self.fields + self.kw)
        d['c'] = self.control
        return d

    def pack(self):
        if hasattr(self, 'dest') and not self.hdr.dest:
            self.hdr.dest = self.dest
        return msgpack.packb(self.hdr) + msgpack.packb(self.values())

    _ = property(pack)

    def header(self, **kw):
        self.hdr = SafeDictWrapper(kw)

    @classmethod
    def set_header(cls, packed, header):
        p = msgpack.Unpacker()
        p.feed(packed)
        data = []
        while True:
            try:
                hdr = p.unpack()
                hdr.update(header)
                data.append(msgpack.packb(hdr))
                p.skip(lambda p: data.append(p))
            except msgpack.OutOfData:
                break
        return ''.join(data)

    @classmethod
    def pop_header(cls, packed):
        p = msgpack.Unpacker()
        p.feed(packed)
        plain_data = ''
        hdr = SafeDictWrapper()
        while True:
            try:
                clean_hdr = p.unpack()
                data = []
                for k in ['ident', 'peer', 'org']:
                    hdr[k] = clean_hdr.pop(k, '')
                p.skip(lambda p: data.append(p))
                plain_data = msgpack.packb(clean_hdr) + data[0]
            except msgpack.OutOfData:
                break
        return hdr, plain_data

    @classmethod
    def parse(cls, packed):
        p = msgpack.Unpacker()
        p.feed(packed)
        msgs = []
        while True:
            try:
                hdr = p.unpack()
                data = []
                p.skip(lambda p: data.append(p))
                obj = MsgWrapper(hdr, data[0])
                obj.hdr = SafeDictWrapper(hdr)
                msgs.append(obj)
            except msgpack.OutOfData:
                break
            except Exception, ex:
                LOG.exception(ex)
                LOG.error(packed)
                break
        return msgs

    @classmethod
    def build(cls, packed):
        try:
            p = msgpack.Unpacker()
            p.feed(packed)
            hdr = p.unpack()
            kwargs = p.unpack()
            obj = cls(**kwargs)
            obj.hdr = SafeDictWrapper(hdr)
            return obj
        except msgpack.OutOfData:
            LOG.error("Corrupted packet %s" % packed)
            return False


class MsgWrapper(object):

    def __init__(self, header, packed):
        self.hdr = SafeDictWrapper(header)
        self.packed = packed

    def __repr__(self):
        return self._

    def pack(self):
        return msgpack.packb(self.hdr) + self.packed

    _ = property(pack)

    def route(self):
        return [getattr(self.hdr, 'dest'), self.pack()]


class Dispatch(M):

    dest = ''
    fields = ["user", "roles", "tasks", "includes", "attachments", "env",
              "disabled_nodes"]


class GetNodes(M):

    dest = ''
    fields = ["org"]


class Nodes(M):

    dest = ''
    fields = ["nodes"]


class Queued(M):

    dest = ''
    fields = ["task_ids"]


class Error(M):

    dest = ''
    fields = ["msg", "code"]


class Fwd(M):

    fields = ['fwd_data']


class Ident(M):

    dest = HEARTBEAT
    fields = ['meta']


class Welcome(M):

    dest = ''
    fields = []


class Reload(M):

    dest = ''
    fields = []


class HB(M):

    dest = HEARTBEAT
    fields = []


class HBR(M):

    dest = HEARTBEAT
    fields = ['node', 'usage']


class Ping(M):

    dest = HEARTBEAT
    fields = []


class Init(M):
    fields = ['org_id', 'org_name', 'session_key', 'session_iv']


class Quit(M):
    dest = HEARTBEAT
    fields = ['peer']


class Term(M):
    fields = ['dest', 'reason', 'signal']


class Input(M):
    fields = ['dest', 'cmd', 'data']


class Crypto(M):
    dest = ''
    fields = ['message']


class JobTarget(M):
    dest = ''
    fields = ['job_id', 'targets']

# Replies


class Register(M):
    dest = ADMIN_TOWER
    fields = ['node', 'data', 'meta']


class Control(M):
    fields = ['node', 'status', 'message']


class StdOut(M):
    fields = ['dest', 'job_id', 'run_as', 'output']


class StdErr(M):
    fields = ['dest', 'job_id', 'run_as', 'output']


class FileExport(M):
    fields = ['dest', 'job_id', 'file_name', 'content']


class Finished(M):
    fields = ['dest', 'job_id', 'run_as', 'result']


class Events(M):
    fields = ['dest', 'job_id', 'run_as', 'result']


class Job(M):
    fields = ['job_id', 'remote_user', 'request']


class LocalJobRep(M):

    fields = ['dest', 'job_id', 'peer', 'control', 'run_as', 'data']

# Node


class Ready(M):
    run_as = ''
    fields = ['dest', 'status']

# Transport


class InitialMessage(M):
    status = StatusCodes.STARTED
    type = "INITIAL"
    fields = ["type", "session_id", "ts", "org", "user", "seq_no"]


class PipeMessage(M):
    status = StatusCodes.PIPEOUT
    fields = ["type", "session_id", "ts", "seq_no", "org",
              "user", "run_as", "node", "stdout", "stderr"]

    type = "PARTIAL"


class FinishedMessage(M):
    status = StatusCodes.FINISHED
    fields = ["type", "session_id", "ts",
              "user", "org", "result", "env"]

    type = "FINISHED"
