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
if os.name != 'nt':
    try:
        from unittest import SkipTest
    except ImportError:
        from unittest2 import SkipTest
    raise SkipTest(
        "The rest of this code will not be run on Linux.")

import ntsecuritycon as ntsec
import win32security as winsec

PERM_MAP = {
    'R': ntsec.FILE_GENERIC_READ,
    'W': ntsec.FILE_GENERIC_WRITE | ntsec.FILE_APPEND_DATA,
    'E': ntsec.FILE_GENERIC_EXECUTE,
}


def chmod(path, uid, *modes):
    return  # Skip for now
    file_acl = winsec.ACL()
    mode_map = {'O': 0, 'G': 0, 'I': 0}
    for m in modes:
        if m.startswith('I'):
            assert m[0] in mode_map
            mode_map[m[0]] |= PERM_MAP[m[1]]

    if mode_map['O']:
        everyone = winsec.LookupAccountName("", "Everyone")
        file_acl.AddAccessAllowedAce(winsec.ACL_REVISION,
                                     mode_map['O'], everyone[0])
    if mode_map['G']:
        admins = winsec.LookupAccountName("", "Administrators")
        file_acl.AddAccessAllowedAce(winsec.ACL_REVISION,
                                     mode_map['G'], admins[0])
    if mode_map['I']:
        file_acl.AddAccessAllowedAce(winsec.ACL_REVISION,
                                     mode_map['I'], uid)

    sec_desc = winsec.GetFileSecurity(path,
                                      winsec.DACL_SECURITY_INFORMATION)
    sec_desc.SetSecurityDescriptorDacl(1, file_acl, 0)
    winsec.SetFileSecurity(path,
                           winsec.DACL_SECURITY_INFORMATION,
                           sec_desc)


def chown(path, uid, gid):
    pass
