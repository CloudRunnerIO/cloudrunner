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

    def _decode(self, string, encodings=['utf-8', 'utf-16',
                                         'Windows-1252',
                                         'latin1']):
        for enc in encodings:
            try:
                s = string.decode(enc)
                return s
            except UnicodeDecodeError:
                continue
        # Fallback - decode to UTF8 with ignoring un-recognized characters
        return string.decode('utf-8', 'ignore')

    def run(self):
        for line in iter(self.pipe.readline, ''):
            with self.lock:
                line = line.strip()
                if line and line != '\x00':
                    self._buf.write(self._decode(line))
                    self._buf.write("\n")

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
