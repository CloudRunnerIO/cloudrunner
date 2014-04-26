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

import ConfigParser
import logging
import os

BOOL_VALUES = {'true': True, 'True': True,
               'false': False, 'False': False}

LOG = logging.getLogger("Config")


class Mapper(object):

    def __getattr__(self, key):
        if self._config.has_option(self._section, key):
            val = self._config.get(self._section, key)
            if val in BOOL_VALUES.keys():
                return BOOL_VALUES[val]
            else:
                return val
        else:
            return None

    __getitem__ = __getattr__


class Config(Mapper):

    def __init__(self, config_file):
        self._fn = config_file
        self.reload()
        self._section = 'General'

        class Section(Mapper):

            def __init__(self, config, section):
                self._config = config
                self._section = section

            def items(self):
                try:
                    return self._config.items(self._section)
                except:
                    LOG.debug("No section %s found in %s" %
                            (self._section, config_file))
                    return {}

        self.security = Section(self._config, 'Security')
        self.users = Section(self._config, 'Users')
        self.plugins = Section(self._config, 'Plugins')
        self.run_as = Section(self._config, 'Run_as')

    def __str__(self):
        return "Config(%s)" % self._fn

    def __unicode__(self):
        return u"Config(%s)" % self._fn

    def update(self, section, key, value):
        """
        Update values in config.
        """
        if not self._config.has_section(section):
            self._config.add_section(section)
        self._config.set(section, key, value)

        try:
            self._config.write(open(self._fn, 'w'))
        except IOError:
            if not os.path.exists(os.path.dirname(self._fn)):
                os.makedirs(os.path.dirname(self._fn))
                self._config.write(open(self._fn, 'w'))
            else:
                raise

    def reload(self):
        self._config = ConfigParser.ConfigParser()
        try:
            self._config.read(self._fn)
        except Exception, ex:
            print "Config not found %s" % ex
