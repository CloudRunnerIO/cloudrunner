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

import os

from cloudrunner.util.shell import colors


class CertStore(object):

    SEP = '\t'

    def __init__(self, store_fn):
        self.store_fn = store_fn
        self._store = set()
        self.reload()

    def reload(self):
        try:
            f = open(self.store_fn, 'r')
        except Exception:
            if not os.path.exists(self.store_fn):
                if not os.path.exists(os.path.dirname(self.store_fn)):
                    os.makedirs(os.path.dirname(self.store_fn))
                f = open(self.store_fn, 'w')
                f.write('')
                f.close()
                f = open(self.store_fn, 'r')
        for l in f:
            data = l.strip()
            if data:
                try:
                    cn, _, fprint = data.rpartition(self.SEP)
                    if cn and fprint:
                        self._store.add((cn, fprint))
                except:
                    pass

    def get_fingerprint(self, common_name):
        for (cn, fp) in self._store:
            if cn == common_name:
                return fp

    def get_common_name(self, fingerprint):
        for (cn, fp) in self._store:
            if fp == fingerprint:
                return cn

    def __contains__(self, data):
        (cn, fp) = data
        for (_c, _f) in self._store:
            if _c == cn and _f == fp:
                return True

    def __iter__(self):
        return iter(self._store)

    def insert(self, common_name, fingerprint):
        access_key = "%s%s%s" % (common_name, self.SEP, fingerprint)

        with open(self.store_fn, 'r') as f:
            for l in f:
                cn, _, fp = l.partition(self.SEP)
                if fp == fingerprint:
                    print colors.red(
                        "The specified fingerprint already exists. "
                        "You should first unregister it.")
                    return False
                if cn == common_name and fp != fingerprint:
                    print colors.red(
                        "The specified common name already exists. "
                        "You should first unregister it.")
                    return False

        with open(self.store_fn, 'a') as f:
            f.write('\n%s' % access_key)
            f.close()
            print colors.blue("Fingerprint for %s was added" %
                              common_name)
        self.reload()
        return True

    def remove(self, common_name=None, fingerprint=None):
        if not common_name and not fingerprint:
            print colors.red("You should specify either common name or "
                             "fingerprint to be removed.")
            return False

        keys = []
        with open(self.store_fn, 'r') as f:
            for l in f:
                cn, _, fp = l.strip().rpartition(self.SEP)
                if common_name != cn and fingerprint != fp:
                    keys.append("%s%s%s" % (cn, self.SEP, fp))

        f = open(self.store_fn, 'w')
        f.write('\n'.join(keys))
        f.close()
        print colors.blue("Fingerprint/Common name %s/%s was removed" %
                          (common_name, fingerprint))
        self.reload()
        return True
