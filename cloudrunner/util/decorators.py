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
from functools import wraps

LOG = logging.getLogger('wrapper')


def catch_ex(message=None, to_exit=True):
    def method_wrapper(f):
        @wraps(f)
        def wrapper(*args, **kwds):
            try:
                return f(*args, **kwds)
            except Exception, ex:
                if message:
                    m = message.format(f.__name__, ex)
                else:
                    m = "Error executing [%s]:%s" % (f.__name__, ex)
                LOG.error(m)
                if to_exit:
                    exit(1)
        return wrapper
    return method_wrapper
