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

from cloudrunner.plugins.state.base import StatePluginBase

ENV_FILE_NAME = "__ENV__FILE__"
DISABLED_ENV = ('_', 'PIPESTATUS', ENV_FILE_NAME, '___ENV___')

LOG = logging.getLogger('StateManager')


class StateManager(object):

    """
        Base class for processing State for executed code
    """

    def __init__(self):
        # Load processing plugins
        self.processors = dict()
        plugins = StatePluginBase.__subclasses__()

        for plugin in plugins:
            if hasattr(plugin, 'lang'):
                self.processors[plugin.lang] = plugin
                LOG.debug('Loaded plugin: %s' % plugin)
        self.proc = None

    def set_state_handlers(self, lang, uid, gid, cwd, command, env):
        proc_class = self.processors.get(lang, None)
        if not proc_class:
            return command, '', {}

        self.proc = proc_class(uid, gid, cwd, env)
        (pre, post, suffix) = self.proc.set_state_handlers()
        if hasattr(proc_class, 'process_env'):
            env = proc_class.process_env(env)
        command = "%s\n%s\n%s" % (pre, command, post)
        return command, suffix, env

    def get_exec_commands(self, lang, exec_file_name):
        proc_class = self.processors.get(lang, None)
        if not proc_class:
            return [exec_file_name]
        if hasattr(proc_class, 'exec_params'):
            return proc_class.exec_params(exec_file_name)

        return [exec_file_name]

    def save_state(self):
        if not self.proc:
            return {}
        return self.proc.save_state()
