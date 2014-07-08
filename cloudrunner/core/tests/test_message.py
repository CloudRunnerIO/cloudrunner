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

from cloudrunner.core import message
from cloudrunner.tests import base


class TestMessages(base.BaseTestCase):

    def test_agent_req(self):
        _req = message.AgentReq(u"LOGIN", "1", u"TOKEN",
                                u"CONTROL", u"DATA", u'{"EXTRA": "Value"}')

        _req.append(control="NEW_CONTROL")
        _req.append(data="changed data")
        _req.append(custom="custom element")

        packed = _req.pack()

        for data in packed:
            self.assertType(data, str)
        self.assertEqual(packed[3], "NEW_CONTROL")
        self.assertEqual(packed[4], "changed data")
        self.assertContains(packed[5], "custom element")

    def test_sched_req(self):
        _req = message.ScheduleReq.build(u"NEW", u"JOB ID")
        self.assertType(_req, message.ScheduleReq)

        self.assertEqual(_req.pack(), ["NEW", "JOB ID"])
