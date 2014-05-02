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
from socket import gethostname
import platform
import re

from cloudrunner.version import VERSION
from cloudrunner.util.net import get_local_ips

SPLITTER = re.compile(r'\s+|,|;')

LOG = logging.getLogger('Matcher')


class Matcher(object):

    """
        Provides basic matching functions for node targets
    """

    def __init__(self, node_id):
        self.props = {}
        self.node_id = node_id
        self.host = gethostname().lower()
        self.os = platform.system()
        self.arch = platform.machine()
        try:
            # only OS, not version
            self.dist = platform.linux_distribution()[0]
            if not self.dist:
                # Try a hack for ArchLinux
                self.dist = platform.linux_distribution(
                    supported_dists=('arch'))[0]  # only OS, not version
        except:
            # Python < 2.6
            self.dist = platform.dist()[0]  # only OS, not version
        self.release = platform.release()
        self.ips = []
        try:
            self.ips = get_local_ips()
        except:
            pass
        if not self.ips:
            LOG.warn("No IPs were detected")

        self.crn_version = VERSION

    def __setattr__(self, name, value):
        super(Matcher, self).__setattr__(name, value)
        if name != 'props':
            self.props[name] = value

    def is_match(self, target_str):
        targets = SPLITTER.split(target_str)
        targets = [t.strip() for t in targets if t.strip()]

        def _match(target):
            try:
                if '=' in target:
                    # we have specific selector
                    k, _, v = target.partition('=')
                    if not hasattr(self, k):
                        return False
                    return re.match(self.prepare_re(v), getattr(self, k), re.I)
                else:
                    return re.match(self.prepare_re(target), self.node_id, re.I) \
                        or target in self.ips
            except:
                return

        return filter(_match, targets)

    def prepare_re(self, match):
        return '^%s$' % match.replace(".", "\.").replace("*", ".*")
