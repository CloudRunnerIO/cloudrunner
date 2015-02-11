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
from logging.handlers import TimedRotatingFileHandler
import os
from cloudrunner.util.shell import *  # noqa


def configure_loggers(min_level, log_file, log_format=None):
    DEFAULT_LOG_FORMAT = ('%(asctime)s(%(name)s)[%(process)d--%(threadName)s]'
                          '::%(levelname)s - %(funcName)s(%(message)s)')
    blue_pref = '\x1b[' + BLUE
    red_pref = '\x1b[' + RED
    green_pref = '\x1b[' + GREEN
    yellow_pref = '\x1b[' + YELLOW
    suffix = '\x1b[0m'
    COLOR_LOG_FORMAT = '%(asctime)s(' + \
        blue_pref + '%(name)s' + suffix + \
        ')[%(process)d--%(threadName)s]::' + \
        red_pref + '%(levelname)s ' + suffix + '- ' + \
        green_pref + '%(funcName)s' + suffix + \
        yellow_pref + '(%(message)s)' + suffix

    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))

    if log_format:
        _format = log_format
    else:
        if "NO_COLORS" in os.environ:
            _format = DEFAULT_LOG_FORMAT
        else:
            _format = COLOR_LOG_FORMAT
    logging.basicConfig(level=min_level, format=_format)

    formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    file_handler = TimedRotatingFileHandler(log_file, when='midnight')
    file_handler.setLevel(min_level)
    file_handler.setFormatter(formatter)

    logging.getLogger('').addHandler(file_handler)
    logging.getLogger('').setLevel(min_level)
