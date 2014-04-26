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
import re

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


def split_sections(document):
    return re.split(SECTION_SPLIT, document, re.M)


def parse_common_opts(script):
    opts = CRN_SHEBANG.match(script)
    if opts:
        return opts.groups(1)
    else:
        return None
