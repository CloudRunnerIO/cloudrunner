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

import copy
import logging
import os
import shutil
import tempfile
import uuid

SHEBANG = {
    'bash': '/bin/bash',
    'sh': '/bin/sh',
    'python': '/usr/bin/python -u\n# -*- coding: utf-8 -*-',
    'perl': '/usr/bin/perl',
    'ruby': '/usr/bin/ruby',
    'puppet': '/usr/bin/puppet apply',
    'salt': '/usr/bin/salt',
    'nodejs': '/usr/bin/nodejs'
}

COMMENT_SYMBOL = {
    'nodejs': '//'
}

import cloudrunner
from cloudrunner.core.statemanager import StateManager
from cloudrunner.core import parser
from cloudrunner.util.string import stringify, stringify1, jsonify1

if os.name != 'nt':
    from cloudrunner.core.platform.nix import NixProcessor as Executor
else:
    from cloudrunner.core.platform.nt import NtProcessor as Executor

LOG = logging.getLogger('ExecProcessor')


class Processor(object):

    def __init__(self, as_user, work_dir=cloudrunner.TMP_DIR):
        self.state_manager = StateManager()
        self.as_user = as_user
        self.session_cwd = os.path.join(work_dir, uuid.uuid4().hex)
        os.makedirs(self.session_cwd)
        self.executor = Executor(as_user)

    def run(self, command, lang, env, inlines=None):
        """
        Returns ['running_user', 'cmd_status', 'std_out', 'std_err', 'env']
        """
        ret_code = -255

        if not self.executor.ready:
            yield [ret_code, '', '',
                   'Cannot impersonate user %s\n' % self.as_user,
                   env]
            return
        mod_env = copy.copy(env)
        try:
            mod_env['HOME'] = self.executor.get_home()
            mod_env['LOGNAME'] = self.as_user
            mod_env['PWD'] = self.session_cwd
            mod_env['USER'] = self.as_user

            paths = []
            if "PYTHONPATH" in os.environ:
                paths.append(os.environ.get("PYTHONPATH"))
            paths.append(os.path.realpath(os.path.join(
                os.path.dirname(os.path.abspath(cloudrunner.__file__)), '..')))
            paths.append(self.session_cwd)
            mod_env['PYTHONPATH'] = os.pathsep.join(paths)
            uid = self.executor.get_uid()
            gid = self.executor.get_gid()
        except Exception, ex:
            LOG.exception(ex)
            yield [ret_code, '',
                   'Cannot impersonate user %s\n' % self.as_user,
                   {}]
            return

        for key, v in mod_env.items():
            if isinstance(v, list):
                mod_env[key] = list(stringify(*v))
            else:
                mod_env[key] = stringify1(v)
        command = parser.remove_shebangs(command.strip())

        command, suffix, mod_env = self.state_manager.set_state_handlers(
            lang, uid, gid, self.session_cwd, command, mod_env)

        inlines_str = ""
        if inlines:
            inlines_str = "\n".join(inlines)

        command = "%(comm)s %(shebang)s\n\n%(inlines)s\n%(command)s\n" % \
            dict(shebang=SHEBANG[lang if lang in SHEBANG else "bash"],
                 command=command,
                 inlines=inlines_str,
                 comm=COMMENT_SYMBOL.get(lang, '#!'))

        LOG.debug(command)
        (exec_file_fd, exec_file_name) = tempfile.mkstemp(dir=self.session_cwd,
                                                          prefix='cloudr',
                                                          suffix=suffix,
                                                          text=True)

        os.write(exec_file_fd, command)
        os.close(exec_file_fd)

        for root, dirs, files in os.walk(self.session_cwd):
            for _dir in dirs:
                dir_name = os.path.join(root, _dir)
                self.executor.chmod(dir_name, 'IR', 'IW', 'IE')
                self.executor.chown(dir_name, uid, gid)
            for _file in files:
                file_name = os.path.join(root, _file)
                self.executor.chmod(file_name, 'IR', 'IW', 'IE')
                self.executor.chown(file_name, uid, gid)

        stdout, stderr, stderr_ = ('', '', '')

        exec_file_args = self.state_manager.get_exec_commands(lang,
                                                              exec_file_name)
        try:
            # Yield to consume streams
            popen = None
            initial_env = copy.deepcopy(mod_env)
            for k, v in initial_env.items():
                if isinstance(v, list):
                    initial_env[k] = jsonify1(v)
                else:
                    initial_env[k] = stringify1(v)
            popen = self.executor.popen(exec_file_args,
                                        self.session_cwd,
                                        initial_env)
            yield popen
        except OSError, oserr:
            LOG.exception(oserr)
            stderr += '%r' % oserr
        except Exception, ex:
            LOG.exception(ex)
            stderr += '%r' % ex
        finally:
            if popen:
                ret_code, stdout, stderr_ = popen.finalize()

        stderr += stderr_

        new_env = self.state_manager.save_state()

        # remove impersonation vars
        for k in ['HOME', 'LOGNAME', 'PWD', 'USER', 'PYTHONPATH']:
            if k in new_env:
                new_env.pop(k)

        yield [self.executor.as_user, ret_code, stdout, stderr, new_env]

    def clean(self):
        shutil.rmtree(self.session_cwd, True)

    def add_libs(self, name, source):
        try:
            lib_file_name = os.path.join(self.session_cwd, name)
            # Save
            # ensure subdirs
            path = os.path.realpath(os.path.dirname(lib_file_name))
            if not os.path.exists(path):
                os.makedirs(path)

            open(lib_file_name, 'w').write(source.strip())
        except Exception, ex:
            LOG.exception(ex)
