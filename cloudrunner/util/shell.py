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

from threading import Event
from threading import Thread

COLOR_MAP = {
    'red': '31m',
    'green': '32m',
    'yellow': '33m',
    'blue': '34m',
    'purple': '35m',
    'cyan': '36m',
    'grey': '37m',
}

BLUE = COLOR_MAP['blue']
GREEN = COLOR_MAP['green']
RED = COLOR_MAP['red']
YELLOW = COLOR_MAP['yellow']
PURPLE = COLOR_MAP['purple']
CYAN = COLOR_MAP['cyan']
GREY = COLOR_MAP['grey']

PATTERN = '\x1b[%s%s%s\x1b[0m'


class Singleton(object):
    _instances = {}

    def __new__(class_, *args, **kwargs):
        if class_ not in class_._instances:
            class_._instances[class_] = super(Singleton,
                                              class_).__new__(class_,
                                                              *args,
                                                              **kwargs)
        return class_._instances[class_]


class _Colours(Singleton):

    def __init__(self):
        self.enabled = True

    def __getattr__(self, color):
        return lambda *data, **kwargs: self._log(data,
                                                 color=COLOR_MAP.get(color,
                                                                     ''),
                                                 **kwargs)

    def _log(self, data, color='', bold=0):
        def _str(val):
            if isinstance(val, unicode):
                return val.encode('utf8')
            else:
                return str(val)
        if isinstance(data, tuple):
            data = ' '.join([_str(i) for i in data])
        if not self.enabled:
            return data
        if bold:
            bold = '1;'
        else:
            bold = ''
        if color:
            return PATTERN % (bold, color, data)
        else:
            return data

    def disable(self):
        self.enabled = False

    def enable(self):
        self.enabled = True

colors = _Colours()


class Timer(Thread):

    """
    Timer to execute function on specified interval

    arguments::
        interval    -   timeout interval in seconds
        timer_func  -   function to execute
        immediate   -   start running immediately, otherwise first wait,
                        then execute
    """

    def __init__(self, interval, timer_func, immediate=False):
        super(Timer, self).__init__()
        self.stopped = Event()
        self.interval = interval
        self.timer_func = timer_func
        self.immediate = immediate

    def run(self, *args):
        if self.immediate:
            self.timer_func(*args)

        while not self.stopped.is_set():
            self.stopped.wait(self.interval)
            self.timer_func(*args)

    def stop(self):
        self.stopped.set()


class Console(object):

    def __init__(self, verbose=True):
        self.verbose = verbose

    def __getattr__(cls, key):
        def _print(*args, **kwargs):
            if cls.verbose:
                print getattr(colors, key)(*args, **kwargs)
        return _print

    def new_line(self):
        if self.verbose:
            print
