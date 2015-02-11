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

try:
    from collections import OrderedDict
except ImportError:
    # python 2.6 or earlier, use backport
    from ordereddict import OrderedDict
import logging
import os
import re
import shlex

LANG_BASH = "bash"
LANG_PS = "ps"

CRN_SHEBANG = re.compile("^#!\s*([\/\w]*cloudrunner)\s*(.*)", re.M)
SECTION_SPLIT = re.compile("(^#!\s*switch\s*\[.*\].*)", re.M)
SELECTOR = re.compile('(?P<selector>^#!\s*switch\s*'
                      '\[(?P<selectors>.*)\])(?P<args>.*)$')
PARAMS = re.compile('(?P<sel>\S*)(?P<param>\$\S+)')
USR_BIN_ENV = re.compile("#!\s*/usr/bin/env\s*(?P<lang>\w+)")
LANG = re.compile("^#!\s*(?P<lang>\S*)\s*\n?")

if os.name != 'nt':
    DEFAULT_LANG = LANG_BASH
else:
    DEFAULT_LANG = LANG_PS

LOG = logging.getLogger()


def parse_selectors(section):
    """
        Parse section to check if it is a node selector
    """
    match = SELECTOR.match(section)
    if match:
        selectors = match.group(2)
        args = match.group(3)
        return selectors, args
    return (None, None)


def has_params(targets):
    params = PARAMS.findall(targets)
    return params


def parse_lang(section):
    """
        Parse the script language based on the shebang
    """
    is_env = USR_BIN_ENV.match(section.strip())
    if is_env:
        lang = is_env.group(1)
        return lang
    else:
        match = LANG.match(section.strip())
        if match:
            command = match.group(1).lower()
            lang = command.rpartition('/')[2]
            return lang
    return DEFAULT_LANG


def remove_shebangs(script):
    return LANG.sub('', script)


class ParseError(Exception):
    pass


class Args(object):

    def __init__(self, *args, **kwargs):
        self._items = OrderedDict()
        for arg in args:
            k, _, v = arg.partition('=')
            k = k.lstrip('-')
            if not kwargs.get('flatten'):
                self._items.setdefault(k, []).append(v)
            else:
                self._items[k] = v

    def get(self, k, default=None):
        return self._items.get(k, default)

    def items(self):
        return self._items.items()

    def __getattr__(self, k, default=None):
        return self._items.get(k, default)

    def __contains__(self, k):
        return k in self._items

    def __getitem__(self, k):
        return self._items['k']


class Section(object):

    def __init__(self):
        self.timeout = None
        self.args = Args()
        self.args_string = ''
        self.header = ""
        self.body = ""
        self.lang = ""
        self.target = ''

    @property
    def script(self):
        return "%s\n%s" % (self.header, self.body)


def parse_sections(document):
    try:
        strings = re.split(SECTION_SPLIT, document, re.M)
        strings.pop(0)
        sections = []
        for i in range(0, len(strings), 2):
            section = Section()
            section.header = strings[i]
            section.body = strings[i + 1]
            section.lang = parse_lang(strings[i + 1])
            sections.append(section)
            target, args = parse_selectors(section.header)
            section.target = target
            _args = shlex.split(args)
            section.args = Args(*filter(lambda x: x.startswith('--'), _args))
            section.env = Args(*filter(lambda x: not x.startswith('--'),
                                       _args), flatten=True)
            section.args_string = args
        return sections
    except Exception, exc:
        LOG.error(exc)
        raise ParseError("Error parsing script")


def split_sections(document):
    return re.split(SECTION_SPLIT, document, re.M)


def parse_common_opts(script):
    opts = CRN_SHEBANG.match(script)
    if opts:
        return opts.groups(1)
    else:
        return None
