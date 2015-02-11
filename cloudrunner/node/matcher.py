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
import re

SPLITTER = re.compile(r'\s+|,|;')

LOG = logging.getLogger('Matcher')


class CaseInsensitiveDict(dict):

    def __init__(self, dict_):
        super(CaseInsensitiveDict, self).__init__()
        all_keys = dict_.keys()
        for k in all_keys:
            val = dict_.pop(k)
            super(CaseInsensitiveDict, self).__setitem__(k.lower(), val)

    def __setitem__(self, key, value, default=None):
        raise Exception("Dict is readonly")

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def get(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())


class Matcher(object):

    """
        Provides basic matching functions for node targets
    """

    def __init__(self, node_id, meta):
        self.node_id = node_id
        self.meta = CaseInsensitiveDict(meta)

    def is_match(self, target_str):
        targets = SPLITTER.split(target_str)
        targets = [t.strip() for t in targets if t.strip()]

        def _match(target):
            try:
                if '=' in target:
                    # we have specific selector
                    k, _, v = target.partition('=')
                    if k not in self.meta:
                        return False
                    val = self.meta.get(k)
                    if isinstance(val, basestring):
                        return re.match(self.prepare_re(v), self.meta.get(k),
                                        re.I)
                    elif isinstance(val, (int, long)):
                        return int(v) == val
                    elif isinstance(val, float):
                        return float(v) == val
                    else:
                        return False
                else:
                    return re.match(self.prepare_re(target),
                                    self.node_id, re.I)
            except Exception, ex:
                LOG.exception(ex)
                return

        return filter(_match, targets)

    def prepare_re(self, match):
        return '^%s$' % match.replace(".", "\.").replace("*", ".*")
