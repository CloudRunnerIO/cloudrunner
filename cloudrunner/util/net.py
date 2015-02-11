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
import re
from IPy import IP

from .config import Config

LOG = logging.getLogger("Broadcast")


def get_ips():
    private_ips = []
    public_ips = []
    ips = []
    if os.name != 'nt':
        try:
            addresses = os.popen("ifconfig | grep 'inet addr:'").read()
            ips = re.findall(r'inet addr:([\S]+)', addresses)
            for i in sorted(ips):
                ip = IP(i)
                if ip.iptype() == 'PRIVATE':
                    private_ips.append(ip.strNormal())
                else:
                    public_ips.append(ip.strNormal())
        except:
            pass
    return public_ips, private_ips


class HostResolver(object):

    """
    Resolver for host names.
    Enter the host:port combinations to the resolv_host.conf file
    """

    def __init__(self, resolv_file):
        self.resolv_file = resolv_file
        self._init()

    def _check_changed(self):
        curr_time = os.stat(self.resolv_file).st_mtime
        if curr_time != self.f_time:
            self.f_time = curr_time
            self._init()

    def __contains__(self, host):
        self._check_changed()
        return host in self._conf._config.sections()

    def __getitem__(self, key):
        if key not in self:
            return None
        return [item[1] for item in self._conf._config.items(key)]

    def _init(self):
        try:
            self._conf = Config(self.resolv_file)
            self.f_time = os.stat(self.resolv_file).st_mtime
        except:
            pass

    def mappings(self):
        mappings = {}
        self._check_changed()
        for item in self._conf._config.sections():
            mappings[item] = [m[1] for m in self._conf._config.items(item)]

        return mappings

    def add(self, target, name, host):
        if not self._conf._config.has_section(target):
            self._conf._config.add_section(target)
        self._conf._config.set(target, name, host)
        if not os.path.exists(os.path.dirname(self.resolv_file)):
            os.makedirs(os.path.dirname(self.resolv_file))
        self._conf._config.write(open(self.resolv_file, 'w'))

    def remove(self, target, host):
        if not self._conf._config.has_section(target):
            return False
        section = self._conf._config.items(target)
        keys = [k[0] for k in section if k[1] == host]
        if not keys:
            return False

        for k in keys:
            self._conf._config.remove_option(target, k)
        self._conf._config.write(open(self.resolv_file, 'w'))

        return True
