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

import os

from cloudrunner.tests import base
from cloudrunner.core.statemanager import StateManager


class TestState(base.BaseTestCase):

    def test_state_bash(self):
        s_man = StateManager()
        command, suffix, env = s_man.set_state_handlers(
            'bash',
            os.getuid(),
            os.getgid(),
            '/tmp',
            '#!/bin/bash\necho 1',
            {'ENV_PARAM': 'VALUE',
             'INV-PARAM': 'some value',
             'LIST_VAL': ["1", "2"]
             })
        self.assertContains(command, 'ENV_PARAM="VALUE"')
        self.assertContains(command, 'LIST_VAL[0]="1"')
        self.assertContains(command, 'LIST_VAL[1]="2"')
        self.assertContainsNot(command, 'INV-PARAM=')
        self.assertEqual(suffix, '.sh')

    def test_state_python(self):
        s_man = StateManager()
        command, suffix, env = s_man.set_state_handlers(
            'python',
            os.getuid(),
            os.getgid(),
            '/tmp',
            '#!/usr/bin/python\nprint 1',
            {'ENV_PARAM': 'VALUE'})
        self.assertContains(command, '"ENV_PARAM": "VALUE"')
        self.assertEqual(suffix, '.py')

    def test_state_ruby(self):
        s_man = StateManager()
        command, suffix, env = s_man.set_state_handlers(
            'ruby',
            os.getuid(),
            os.getgid(),
            '/tmp',
            '#!/usr/bin/ruby\nprint 1',
            {'ENV_PARAM': 'VALUE'})
        self.assertContains(command, 'ENV["ENV_PARAM"]="VALUE"')
        self.assertEqual(suffix, '.rb')

    def test_state_powershell(self):
        s_man = StateManager()
        command, suffix, env = s_man.set_state_handlers(
            'ps',
            os.getuid(),
            os.getgid(),
            '/tmp',
            'print 1',
            {'ENV_PARAM': 'VALUE'})
        self.assertContains(command, '$env:ENV_PARAM="VALUE"')
        self.assertEqual(suffix, '.ps1')
