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

import httplib
import re


PROTOCOL_RE = re.compile(r'^(http|https|ftp)://')


def parse_url(url):
    is_known_proto = PROTOCOL_RE.match(url)
    if not is_known_proto:
        return None

    proto = is_known_proto.group(1)
    proto_len = len(is_known_proto.group(0))

    proto_host = url[proto_len:].partition('/')[0]
    file_name = url[proto_len + len(proto_host):]

    return (proto, proto_host), file_name


def load_from_link(proto_url, file_name, auth_user=None, auth_token=None):
    """
    Loads a script from an URL.
    If remote_auth is provided - passes user,token for authentication
    using HTTP Headers for HTTP(S) and user/pass for FTP
    """
    (proto, proto_host) = proto_url

    # Load remotely
    if proto in ('http', 'https'):
        conn = httplib.HTTPConnection(proto_host) if \
            proto == 'http' else \
            httplib.HTTPSConnection(proto_host)
        headers = {}

        if auth_user and auth_token:
            headers = {
                'CloudRunner-User': auth_user,
                'CloudRunner-Token': auth_token,
            }
        try:
            conn.request('GET', file_name, headers=headers)
            res = conn.getresponse()
            if res.status != 200:
                return res.status, res.read()
            else:
                return 0, res.read()
        except Exception, ex:
            return -1, str(ex)
    elif proto == 'ftp':
        try:
            from ftplib import FTP
        except ImportError:
            return -1, "You need python-ftplib to pass scripts as FTP"
        try:
            conn = FTP(proto_host)
            if auth_user and auth_token:
                conn.login(auth_user, auth_token)
            else:
                conn.login()
            return 0, conn.retrlines('RETR %s' % file_name)
        except Exception, ex:
            return -1, str(ex)
