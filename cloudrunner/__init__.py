#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 CloudRunner.IO
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

if os.name != 'nt':
    if os.geteuid() == 0:
        _etc = '/etc/cloudrunner/'
        _var = '/var/'
    else:
        _etc = os.path.expanduser('~/.cloudrunner/')
        _var = os.path.expanduser('~/.cloudrunner/var/')
else:
    _etc = 'c:\\etc\\cloudrunner\\'
    _var = 'c:\\var\\'

VAR_DIR = _var

CONFIG_DIR = _etc

LIB_DIR = os.path.join(VAR_DIR, "lib")
TMP_DIR = os.path.join(VAR_DIR, "tmp")
LOG_DIR = os.path.join(VAR_DIR, "log")

# MASTER CONFIG
CONFIG_LOCATION = os.environ.get('CLOUDRUNNER_CONFIG',
                                 os.path.join(_etc, 'cloudrunner.conf'))

# NODE CONFIG
CONFIG_NODE_LOCATION = os.environ.get("CLOUDRUNNER_NODE_CONFIG",
                                      os.path.join(_etc,
                                                   'cloudrunner-node.conf'))

NODE_LOG_LOCATION = os.path.join(_var, 'log', 'cloudrunner-node.log')
LOG_LOCATION = os.path.join(_var, 'log', 'cloudrunner-dsp.log')
