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

import imp
import inspect
import logging
import sys

from cloudrunner.plugins import PLUGIN_BASES

LOG = logging.getLogger('PluginLoader')


def local_plugin_loader(klass):
    try:
        (mod, _, klass) = klass.rpartition('.')
        if mod not in sys.modules:
            sys.modules[mod] = __import__(mod, globals(), locals(), [''])
        _module = sys.modules[mod]
        _klass = getattr(_module, klass)
        return _klass
    except ImportError as exc:
        LOG.error("Failed to load module %s" % klass, exc_info=True)
        return None
    except AttributeError:
        LOG.error("Failed to load module %s" % klass)
        return None


def load_plugins(config, bases=PLUGIN_BASES):
    plugins = {}
    items = sorted(config.plugins.items(), key=lambda x: x[0])

    plugin_module = imp.new_module('cloudrunner.plugins.custom')
    sys.modules['cloudrunner.plugins.custom'] = plugin_module
    for (item, value) in items:
        if '.' in item:
            # Set plugin property
            (plugin_name, _, conf) = item.partition('.')
            if '.' in conf or plugin_name not in plugins:
                # invalid property or no plugin
                continue
            for p in plugins[plugin_name]:
                setattr(p, conf, value)
        else:
            # Instantiate plugin
            try:
                plugins[item] = load_plugins_from(value, bases)
            except IOError, iex:
                LOG.error('Problem loading %s' % value)
                LOG.error(iex)
            except ImportError, imp_err:
                LOG.error('Problem loading %s' % value)
                LOG.error(imp_err)
            except Exception, err:
                LOG.error('Problem loading %s' % value)
                LOG.error(err)
    return plugins


def load_plugins_from(module_str, base_filter):
    classes = []
    if "/" in module_str or module_str.endswith(".py"):
        mod_name = module_str.rpartition('/')[2]
        mod_name = mod_name.rpartition('.')[0]
        mod_ref = 'cloudrunner.plugins.custom.' + mod_name
        _mod = imp.load_source(mod_ref, module_str)
        classes = set()
        for memb in inspect.getmembers(_mod, inspect.isclass):
            try:
                if issubclass(memb[1], tuple(base_filter)) \
                        and not memb[1] in base_filter:
                    classes.add(memb[1])
            except:
                pass
        return list(classes)
    else:
        tokens = module_str.split('.')

        m = None
        path = None
        for mod in tokens:
            if path:
                m_info = imp.find_module(mod, m.__path__)
            else:
                m_info = imp.find_module(mod)
            if m_info:
                m = imp.load_module(mod, *m_info)
            if path:
                path = path + "." + mod
            else:
                path = mod
        if m:
            classes = []
            for memb in inspect.getmembers(m, inspect.isclass):
                try:
                    if issubclass(memb[1], tuple(base_filter)) \
                       and not memb[1] in base_filter:
                        classes.append(memb[1])
                except:
                    pass
    return classes
