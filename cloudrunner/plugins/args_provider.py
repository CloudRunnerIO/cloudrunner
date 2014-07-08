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


class ArgsProvider(object):

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def append_args(self, arg_parser):
        pass


class CliArgsProvider(object):

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def append_cli_args(self, arg_parser):
        pass

    @abc.abstractmethod
    def call(self, user_id, data, args, ctx):
        pass


class ManagedPlugin(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def start(self):
        pass

    @abc.abstractmethod
    def stop(self):
        pass
