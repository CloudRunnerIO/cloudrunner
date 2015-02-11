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
import os

from unittest import TestCase

import cloudrunner.plugins as plugins
from cloudrunner.util.config import Config
from cloudrunner.util.loader import load_plugins

CONF_FILE = os.path.join(os.path.dirname(__file__), 'test.conf')
_PLUGINS = [('common',
             os.path.join(os.path.dirname(plugins.__file__),
                          "state/functions.py"))]
CONFIG = Config(CONF_FILE)
CONFIG.plugins.items = lambda: _PLUGINS

LOG = logging.getLogger("BaseTest")


class BaseTestCase(TestCase):

    @classmethod
    def setUpClass(cls):
        load_plugins(CONFIG)
        if hasattr(cls, 'fixture_class'):
            cls.fixture_class()
        if not hasattr(TestCase, 'assertIsNotNone'):
            def _assertIsNotNone(cls, val):
                cls.assertNotEqual(val, None)
            TestCase.assertIsNotNone = _assertIsNotNone
        if not hasattr(TestCase, 'assertIsNone'):
            def _assertIsNone(cls, val):
                cls.assertEqual(val, None)
            TestCase.assertIsNone = _assertIsNone

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'release_class'):
            cls.release_class()

    def setUp(self):
        if hasattr(self, 'fixture'):
            self.fixture()

    def tearDown(self):
        if hasattr(self, 'release'):
            self.release()

    @classmethod
    def _print(cls, msg):
        LOG.error(msg)

    def assertContains(self, where, what):
        self.assertTrue(what in where,
                        "[%s] not found in [%s] " % (what, where))

    def assertContainsNot(self, where, what):
        self.assertFalse(what in where,
                         "[%s] not found in [%s] " % (what, where))

    def assertType(self, obj, _type):
        self.assertTrue(isinstance(obj, _type),
                        "(%s) %s is not %s" % (obj, type(obj), _type))

    def assertCount(self, _list, count):
        self.assertEqual(len(_list), count)
