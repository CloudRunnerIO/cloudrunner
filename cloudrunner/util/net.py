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
import select
import socket
from struct import pack
import threading
import time
from Queue import Queue, Empty

from .config import Config

LOG = logging.getLogger("Broadcast")


def get_local_ips():
        def udp_listening_server():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         pack('ii', 0, 0))
            try:
                s.bind(('<broadcast>', 5558))
            except:
                LOG.warn("Cannot start broadcast listener")
                return

            s.setblocking(0)
            while True:
                result = select.select([s], [], [])
                msg, address = result[0][0].recvfrom(1024)
                msg = str(msg)
                if msg == 'What is my LAN IP address?':
                    break
            queue.put(address)
            s.close()

        queue = Queue()
        thread = threading.Thread(target=udp_listening_server)
        thread.queue = queue
        thread.start()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, pack('ii', 0, 0))
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        has_tries = 10
        ips = []
        while has_tries:
            s2.sendto(
                bytes('What is my LAN IP address?'), ('<broadcast>', 5558))
            try:
                address = queue.get(False)
                ips.append(address[0])
            except Empty:
                time.sleep(.2)
                has_tries -= 1
            else:
                break
        s2.close()
        return ips


class HostResolver(object):

    """
    Resolver for host names.
    Enter the host:port combinations to the resolv_host.conf file
    """

    SECTION = "Nodes"

    def __init__(self, resolv_file):
        self.resolv_file = resolv_file
        self._init(resolv_file)

    def __contains__(self, host):
        return bool([item[1] for item in self._conf.nodes.items()
                     if item[0] == host])

    def __getitem__(self, key):
        if key not in self:
            return None
        host = [item[1] for item in self._conf.nodes.items()
                if item[0] == key][0]
        return host

    def _init(self, resolv_file):
        try:
            self._conf = Config(resolv_file)
            self._conf.add_section("nodes", self.SECTION)
        except:
            pass

    def add(self, name, host):
        if not self._conf._config.has_section(self.SECTION):
            self._conf._config.add_section(self.SECTION)
        self._conf._config.set(self.SECTION, name, host)
        if not os.path.exists(os.path.dirname(self.resolv_file)):
            os.makedirs(os.path.dirname(self.resolv_file))
        self._conf._config.write(open(self.resolv_file, 'w'))
