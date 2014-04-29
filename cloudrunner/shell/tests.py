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

from cloudrunner.tests.base import BaseTestCase
from cloudrunner import CONFIG_SHELL_LOC
from cloudrunner.util.config import Config
from cloudrunner.plugins.transport.zmq_transport import ZmqCliTransport


class TestController(BaseTestCase):

    def test_run_local(self):
        transport = ZmqCliTransport()
        transport.configure(overwrite=True)

        CONFIG = Config(CONFIG_SHELL_LOC)
        from cloudrunner.shell.api import CloudRunner
        cr = CloudRunner.from_config(CONFIG)
        async_res = cr.run_local("echo 123")

        it = async_res.iter()
        pipe_msg = next(it)

        self.assertEqual(pipe_msg.node, "localhost")
        self.assertEqual(pipe_msg.stdout, "123\n")

        cr.close()
