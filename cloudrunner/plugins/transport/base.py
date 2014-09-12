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


class TransportBackend(object):

    __metaclass__ = abc.ABCMeta

    config_options = []
    properties = []

    @abc.abstractmethod
    def configure(self, overwrite=False, **kwargs):
        pass

    @abc.abstractmethod
    def consume_queue(self, type, ident=None, *args, **kwargs):
        pass

    @abc.abstractmethod
    def publish_queue(self, type, ident=None, *args, **kwargs):
        pass

    @abc.abstractmethod
    def create_poller(self, *sockets):
        pass

    @abc.abstractmethod
    def prepare(self):
        pass

    @abc.abstractmethod
    def terminate(self, force=False):
        pass

    @abc.abstractmethod
    def loop(self):
        pass

    @classmethod
    def from_config(cls, config, **kwargs):
        conf = kwargs
        for opt in cls.config_options:
            tokens = opt.split('.')
            _target = config
            for token in tokens:
                val = getattr(_target, token, "!SKIP")
                if val == "!SKIP":
                    break
                _target = val
            if val != "!SKIP":
                prop_key = opt.rpartition('.')[2]
                conf[prop_key] = val
        override_kwargs = dict((key, val) for key, val in kwargs.items()
                               if key in cls.config_options
                               and val is not None)
        conf.update(override_kwargs)
        return cls(**conf)


class Endpoint(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def fd(self, *frames):
        pass

    @abc.abstractmethod
    def send(self, *frames):
        pass

    @abc.abstractmethod
    def recv(self, timeout=None):
        pass

    @abc.abstractmethod
    def recv_nb(self, timeout=None):
        pass

    @abc.abstractmethod
    def close(self):
        pass


class Poller(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def poll(self, timeout=0):
        pass
