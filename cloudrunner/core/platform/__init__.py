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

import StringIO
import threading


class AsyncPipeReader(threading.Thread):

    def __init__(self, pipe):
        threading.Thread.__init__(self)
        self.pipe = pipe
        self._buf = StringIO.StringIO()
        self.lock = threading.Lock()

    def run(self):
        for line in iter(self.pipe.readline, ''):
            with self.lock:
                self._buf.write(line)

    def read(self):
        # Consume current data and flush buffer
        self.lock.acquire()
        data = self._buf.getvalue()
        self._buf.truncate(0)
        self.lock.release()
        return data

    def close(self):
        self._buf.close()

    def has_data(self):
        return self._buf.len
