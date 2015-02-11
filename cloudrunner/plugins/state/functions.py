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

import json
import logging
import os
import platform
import re
import tempfile

from cloudrunner.plugins.state.base import StatePluginBase
if os.name == 'nt':
    from cloudrunner.util.nt import chmod
    from cloudrunner.util.nt import chown
else:
    from cloudrunner.util.nix import chmod
    from cloudrunner.util.nix import chown

ENV_FILE_NAME = "__ENV__FILE__"
ENV_SEP = "__ENV__SEP__LINE__"
SPECIAL = ('HOME', 'PWD', 'LOGNAME', 'USER', 'PYTHONPATH')
DISABLED_ENV = SPECIAL + ('_', 'PIPESTATUS', ENV_FILE_NAME,
                          '___ENV___', 'SHELLOPTS',
                          'BASH_LINENO', 'BASH_SOURCE',
                          'FUNCNAME', 'IFS', 'PS4')
KEY_RE = re.compile(r'^\S*$', re.S)
BASH_VARS = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
LOG = logging.getLogger("StateFunctions")


def escape(val):
    return val.replace('"', '\\"')


class Base(object):

    def __init__(self, uid, gid, cwd, env):
        (state_file, state_file_name) = tempfile.mkstemp(dir=cwd,
                                                         prefix='cloudr',
                                                         suffix="_state",
                                                         text=True)
        chmod(state_file_name, 'IR', 'IW', 'IE')
        chown(state_file_name, uid, gid)

        self.env = env
        self.state_file_name = state_file_name
        os.close(state_file)
        self.env[ENV_FILE_NAME] = state_file_name.replace('\\', '\\\\')

    def save_state(self):
        new_env = self.parse_state_file(self.state_file_name)
        if ENV_FILE_NAME in new_env:
            new_env.pop(ENV_FILE_NAME)
        return new_env

    def parse_state_file(self, state_file_name):
        state_file = open(state_file_name)
        _lines = state_file.read()
        state_file.close()

        _lines = re.sub(
            r'\w*\s\(.*\)\s*\{?\s(\s{4}.*\s)+\}?', '', _lines, re.S)
        lines = [line for line in _lines.split('\n') if line]

        def clean(val):
            if val.startswith("$'"):  # quoted value
                val = val.lstrip("$")  # remove $ sign
                val = val[1:-1]  # remove apostrophes
            if val.startswith('"') and val.endswith('"'):
                val = val.strip('"')
            if val.startswith("'") and val.endswith("'"):
                val = val.strip("'")
            return val

        start_escaped = False
        append_to = None
        new_env = {}
        for line in lines:
            line = line.strip()
            (k, _, v) = line.partition("=")
            if v.startswith("'") and not v[1:].endswith("'"):
                start_escaped = True
                append_to = k
                new_env.setdefault(append_to, [''])
                new_env[append_to][-1] = new_env[
                    append_to][-1] + clean(v).lstrip("'")
                continue

            if start_escaped:
                new_env[append_to][-1] = new_env[
                    append_to][-1] + clean(line).rstrip("'")

                if line.endswith("'"):
                    start_escaped = False
                continue

            if k not in DISABLED_ENV and KEY_RE.match(k):
                new_env[k] = clean(v)

        os.unlink(state_file_name)
        return new_env


class Python(Base, StatePluginBase):
    lang = "python"

    def set_state_handlers(self):
        prepare_e = []
        prepare_e.append("import imp")
        current_file = __file__.replace('\\', '\\\\')
        if current_file.endswith(".pyc"):
            current_file = current_file[:-1]
        prepare_e.append(
            "env_string_proxy = imp.load_source('env_string_proxy', '%s')" %
            current_file)
        prepare_e.append("from env_string_proxy import __enter, __exit")
        prepare_e.append("global __env__old__items")
        prepare_e.append("__enter('%s')" % json.dumps(self.env).replace("'",
                                                                        "\\'"))
        prepare_env = "\n".join(prepare_e)

        store_env = "__exit(0)"

        # Touch __init__.py for lib import
        exec_dir = os.path.dirname(self.env[ENV_FILE_NAME])
        open(os.path.join(exec_dir, '__init__.py'), 'w').write('')

        return (prepare_env, store_env, ".py")

    def parse_state_file(self, state_file_name):
        state_file = open(state_file_name)
        _lines = state_file.read()
        state_file.close()

        after = {}
        lines = [line.strip() for line in _lines.split('\n') if line.strip()]

        for line in lines:
            k, _, v = line.partition('=')
            if k in DISABLED_ENV or not KEY_RE.match(k):
                continue
            try:
                after[k] = json.loads(v)
            except:
                continue

        os.unlink(state_file_name)
        return after


class Ruby(Base, StatePluginBase):
    lang = "ruby"

    def set_state_handlers(self):
        prepare_env = "$__env__old__items = ENV.to_hash\n"
        for k, v in self.env.items():
            if k[0].isdigit():
                continue  # cannot start with digit
            if not isinstance(v, list):
                v = [v]
            for i in range(len(v)):
                prepare_env += 'ENV["%s"]="%s"\n' % (k, v[i])
        store_env = """
$__env__new__items = ENV.to_hash

__DIFF__ = ($__env__old__items.size > $__env__new__items.size) \
? $__env__old__items.to_a - $__env__new__items.to_a \
: $__env__new__items.to_a - $__env__old__items.to_a

File.open('%s', 'w') { |file|
  Hash[*__DIFF__.flatten].each {|key, value|
    file.write( "#{key}=#{value}\n" )
  }
}
""" % self.env[ENV_FILE_NAME]
        return (prepare_env, store_env, ".rb")


class Perl(Base, StatePluginBase):
    lang = "perl"

    @staticmethod
    def exec_params(exec_file_name):
        if os.name == 'nt':
            return ["perl", exec_file_name]
        else:
            return [exec_file_name]

    def set_state_handlers(self):
        prepare_env = ""
        store_env = ""
        return (prepare_env, store_env, ".pl")


class Sh(Base, StatePluginBase):
    lang = "sh"

    def set_state_handlers(self):
        prepare_env = []
        prepare_env.append('set +e')
        prepare_env.append('set +v')
        for k, v in self.env.items():
            if not isinstance(v, list):
                v = [v]
            for i in range(len(v)):
                if BASH_VARS.match(k):
                    if len(v) == 1:
                        prepare_env.append('%s="%s"' % (k, escape(v[i])))
                    else:
                        prepare_env.append('%s[%i]="%s"' %
                                           (k, i, escape(v[i])))

        prepare_env.append("""
function __exit(){
  readonly ___ENV2___=$(set)
  awk 'FNR==NR{old[$0];next};!($0 in old)' <(echo \"$___ENV___\") """
                           """<(echo \"$___ENV2___\") > $%(env_var)s
  exit $1
}
readonly ___ENV___=$(set)
readonly %(env_var)s=%(env_file_name)s\n""" %
                           dict(env_var=ENV_FILE_NAME,
                                env_file_name=self.env[ENV_FILE_NAME]))
        store_env = """
set +e
set +v
__exit 0"""
        return ('\n'.join(prepare_env), store_env, '.sh')


START_LINE = re.compile('^declare\s-[\S*]\s+(.*)')
DATA_LINE = re.compile('^\s(.*)')


class Bash(Base, StatePluginBase):
    lang = "bash"

    def set_state_handlers(self):
        prepare_env = []
        prepare_env.append('set +e')
        prepare_env.append('set +v')
        for k, v in self.env.items():
            if not isinstance(v, list):
                v = [v]
            for i in range(len(v)):
                if BASH_VARS.match(k):
                    if len(v) == 1:
                        prepare_env.append('%s="%s"' % (k, escape(v[i])))
                    else:
                        prepare_env.append('%s[%i]="%s"' %
                                           (k, i, escape(v[i])))

        prepare_env.append("""
function __exit(){
  echo -e "$(declare -p)" >> %(env_file_name)s
  exit $1
}
echo -e "$(declare -p)" > %(env_file_name)s
echo %(sep)s >> %(env_file_name)s
readonly %(env_var)s=%(env_file_name)s\n""" %
                           dict(env_var=ENV_FILE_NAME,
                                env_file_name=self.env[ENV_FILE_NAME],
                                sep=ENV_SEP))
        store_env = """
set +e
set +v
__exit 0"""
        return ('\n'.join(prepare_env), store_env, '.sh')

    def parse_state_file(self, state_file_name):
        state_file = open(state_file_name)
        _lines = state_file.read()
        state_file.close()

        before, after = {}, {}
        current = before
        last_key = None

        lines = [line for line in _lines.split('\n') if line]

        for line in lines:
            if line == ENV_SEP:
                current = after
                continue

            m = START_LINE.match(line)
            if m:
                k, _, v = m.group(1).partition('=')
                if k in DISABLED_ENV or not KEY_RE.match(k):
                    continue
                current[k] = v
                last_key = k

            elif line and DATA_LINE.match(line) and last_key:
                current[last_key] += DATA_LINE.match(line).group(1)

        for k, v in before.items():
            if k in after:
                if after[k] == v:
                    after.pop(k)

        os.unlink(state_file_name)
        for k, v in after.items():
            if v.startswith('"') and v.endswith('"'):
                after[k] = v.strip('"')
            if v.startswith("'") and v.endswith("'"):
                after[k] = v.strip("'")

        return after


class NodeJS(Base, StatePluginBase):
    lang = "nodejs"

    def set_state_handlers(self):
        prepare_env, store_env = '', ''
        for k, v in self.env.items():
            if k[0].isdigit():
                continue  # cannot start with digit
            if not isinstance(v, list):
                prepare_env += 'var %s = "%s"\n' % (
                    k, v.replace('"', '\\"'))
            else:
                prepare_env = "var %s = %s;\n" % (k, json.dumps(v))

        return (prepare_env, store_env, '.js')

    @staticmethod
    def exec_params(exec_file_name):
        if platform.dist() in ("Ubuntu", "Debian"):
            # On some distros assume nodejs
            return ["/usr/bin/nodejs", exec_file_name]
        elif os.name == 'nt':
            return ["node", exec_file_name]
        else:
            return ["/usr/bin/node", exec_file_name]


class Puppet(Base, StatePluginBase):
    lang = "puppet"

    def set_state_handlers(self):
        prepare_env = ""
        store_env = ""
        return (prepare_env, store_env, ".pp")

    @staticmethod
    def exec_params(exec_file_name):
        return ["/usr/bin/puppet", "apply", exec_file_name]

    @staticmethod
    def process_env(env):
        keys = env.keys()
        for key in keys:
            if key.startswith("__") or key in DISABLED_ENV or key in SPECIAL:
                continue
            value = env.pop(key)
            env['FACTER_%s' % key] = value
        return env

    def save_state(self):
        return {}


class PowerShell(StatePluginBase):
    lang = "ps"

    def __init__(self, uid, gid, cwd, env):
        (state_file, state_file_name) = tempfile.mkstemp(dir=cwd,
                                                         prefix='cloudr',
                                                         suffix="_state",
                                                         text=True)
        try:
            chmod(state_file_name, uid, 'IR', 'IW', 'IE', 'GR', 'GW')
        except:
            LOG.warn("Cannot set permissions for PowerShell script")

        self.env = env
        self.state_file_name = state_file_name
        os.close(state_file)
        self.env[ENV_FILE_NAME] = state_file_name

    def save_state(self):
        new_env = self.parse_state_file(self.state_file_name)
        if ENV_FILE_NAME in new_env:
            new_env.pop(ENV_FILE_NAME)
        return new_env

    def set_state_handlers(self):
        prepare_env = ""
        for k, v in self.env.items():
            if k[0].isdigit():
                continue  # cannot start with digit
            if not isinstance(v, list):
                v = [v]
            for i in range(len(v)):
                prepare_env += '$env:%s="%s"\n' % (k, v[i])
        store_env = ""
        return (prepare_env, store_env, '.ps1')

    def parse_state_file(self, state_file_name):
        state_file = open(state_file_name)
        lines = state_file.readlines()
        state_file.close()
        new_env = {}
        for line in lines:
            line = line.strip()
            (k, _, v) = line.partition("=")
            if k not in DISABLED_ENV:
                if v.startswith("$'"):  # quoted value
                    v = v.lstrip("$")  # remove $ sign
                    v = v[1:-1]  # remove apostrophes

                if v.startswith('"') and v.endswith('"'):
                    v = v.strip('"')
                if k in new_env:
                    if isinstance(self.env[k], list):
                        new_env[k].append(v)
                    else:
                        new_env[k] = [new_env[k], v]
                else:
                    new_env[k] = v

        os.unlink(state_file_name)
        return new_env

    @staticmethod
    def exec_params(exec_file_name):
        return ["powershell.exe", '-ExecutionPolicy',
                'Unrestricted', '-NonInteractive', '-File', exec_file_name]


def __enter(_env):
    import os
    env = json.loads(_env.replace("\n", "\\n"))
    for k, v in env.items():
        if k == ENV_FILE_NAME:
            os.environ[k] = env[ENV_FILE_NAME]
            continue
        if k in SPECIAL:
            # No special processing here
            os.environ[k] = v
            continue
        if not isinstance(v, list):
            os.environ[k] = v
        else:
            os.environ[k] = StringProxy(v)
    global __env__old__items
    __env__old__items = os.environ.items()


def __exit(exit_code):
    from os import environ
    __env__new__items = environ.items()
    global __env__old__items
    k_v = [(k, v)
           for (k, v) in __env__new__items
           if (k, v) not in __env__old__items]  # noqa
    __env__file = open(environ[ENV_FILE_NAME], 'w')
    for k, v in k_v:
        __env__file.write('%s=%s\n' % (k, json.dumps(v)))
    __env__file.close()
    del __env__old__items
    del __env__new__items

    exit(exit_code)


class StringProxy(str):

    """
    StringProxy class. Usage:
    values = StringProxy([1, 2, 3, 4, 5])

    single_value = values  # returns only 1st object in the list,
                          # useful when the list has only one value

    list_valus = list(values)  # convert to a list
    for value in values:
        use(value)  # enumerate values
    """

    def __init__(self, obj):
        # if obj and len(obj) == 1:
        #    object.__setattr__(self, "_obj", obj[0])
        # else:
        object.__setattr__(self, "_obj", obj)

    #
    # proxying (special cases)
    #
    def __getattribute__(self, name):
        return getattr(object.__getattribute__(self, "_obj"), name)

    def __delattr__(self, name):
        delattr(object.__getattribute__(self, "_obj"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_obj"), name, value)

    def __nonzero__(self):
        return bool(object.__getattribute__(self, "_obj"))

    def __str__(self):
        return str(iter(object.__getattribute__(self, "_obj")).next())

    def __unicode__(self):
        return unicode(iter(object.__getattribute__(self, "_obj")).next())

    def __repr__(self):
        """
        Returns only the first object, in the case only 1 value is passed
        """
        return repr(iter(object.__getattribute__(self, "_obj")).next())

    def __add__(self, other):
        return next(iter(object.__getattribute__(self, "_obj"))) + other

    def __iadd__(self, other):
        return next(iter(object.__getattribute__(self, "_obj"))) + other

    def __radd__(self, other):
        return other + next(iter(object.__getattribute__(self, "_obj")))

    def __iter__(self):
        return iter(object.__getattribute__(self, "_obj"))
    #
    # factories for special function - apply over the original object
    #
    _special_names = [
        '__abs__', '__and__', '__call__', '__cmp__', '__coerce__',
        '__contains__', '__delitem__', '__delslice__', '__div__', '__divmod__',
        '__eq__', '__float__', '__floordiv__', '__ge__',
        '__getslice__', '__gt__', '__hash__', '__hex__', '__iand__',
        '__idiv__', '__idivmod__', '__ifloordiv__', '__ilshift__', '__imod__',
        '__imul__', '__int__', '__invert__', '__ior__', '__ipow__',
        '__irshift__', '__isub__', '__itruediv__', '__ixor__', '__le__',
        '__len__', '__long__', '__lshift__', '__lt__', '__mod__', '__mul__',
        '__ne__', '__neg__', '__oct__', '__or__', '__pos__', '__pow__',
        '__rand__', '__rdiv__', '__rdivmod__', '__reduce__',
        '__reduce_ex__', '__reversed__', '__rfloorfiv__', '__rlshift__',
        '__rmod__', '__rmul__', '__ror__', '__rpow__', '__rrshift__',
        '__rshift__', '__rsub__', '__rtruediv__', '__rxor__', '__setitem__',
        '__setslice__', '__sub__', '__truediv__', '__xor__', 'next'
    ]

    @classmethod
    def _create_class_proxy(cls, theclass):
        assert theclass is list
        """creates a proxy for the given class"""

        def make_method(name):
            def method(self, *args, **kw):
                return getattr(object.__getattribute__(self,
                                                       "_obj"),
                               name)(*args, **kw)
            return method

        namespace = {}
        for name in cls._special_names:
            if hasattr(theclass, name):
                namespace[name] = make_method(name)
        return type("StringProxy", (cls,), namespace)

    def __new__(cls, obj, *args, **kwargs):
        """
        creates an proxy instance referencing `obj`. (obj, *args, **kwargs) are
        passed to this class' __init__, so deriving classes can define an
        __init__ method of their own.
        note: _class_proxy_cache is unique per deriving class (each deriving
        class must hold its own cache)
        """
        try:
            cache = cls.__dict__["_class_proxy_cache"]
        except KeyError:
            cls._class_proxy_cache = cache = {}
        try:
            theclass = cache[obj.__class__]
        except KeyError:
            cache[obj.__class__] = theclass = cls._create_class_proxy(
                obj.__class__)
        # ins = object.__new__(theclass)
        ins = str.__new__(theclass)
        theclass.__init__(ins, obj, *args, **kwargs)
        return ins
