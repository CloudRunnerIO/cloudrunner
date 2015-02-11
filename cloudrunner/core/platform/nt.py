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

import msgpack
import logging
import os
import threading
import subprocess
import win32security as winsec
import win32con
import win32api

from cloudrunner.core.platform import AsyncPipeReader
from cloudrunner.util.nt import chmod


LOG = logging.getLogger('NtProcessor')


class Cred(object):

    def __init__(self, username, password):
        try:
            domain, user = Cred.parse_username(username)
            self.ready = True
        except:
            self.ready = False
        self.domain = domain
        self.username = user
        self.password = password

    @staticmethod
    def parse_username(username):
        domain, _, user = username.rpartition('\\')
        if not domain:
            domain = Cred.get_domain()

        return domain, user

    @staticmethod
    def get_domain():
        return win32api.GetComputerName()


# Based on tornado.ioloop.IOLoop.instance() approach.
# See https://github.com/facebook/tornado
class CredentialManager(object):
    __singleton_lock = threading.Lock()
    __singleton_instance = None

    def __init__(self, credentials_map_file):
        self.credentials = {}
        try:
            with open(credentials_map_file) as f:
                cred_map = msgpack.unpackb(f.read())

            for user, pwd in cred_map.items():
                cred = Cred(user, pwd)
                username = self.get_key(cred.domain, cred.username)
                self.credentials[username] = cred
                LOG.info("Entered credentials for %s" % username)
        except Exception, ex:
            LOG.error(ex)

    def get_key(self, domain, user):
        return '\\'.join([domain, user]).lower()

    def get_cred(self, as_user):
        domain, user = Cred.parse_username(as_user)
        return self.credentials.get(self.get_key(domain, user))

    @classmethod
    def instance(cls, credentials_map_file):
        if not cls.__singleton_instance:
            with cls.__singleton_lock:
                if not cls.__singleton_instance:
                    cls.__singleton_instance = cls(credentials_map_file)
        return cls.__singleton_instance


class NtProcessor(object):

    def __init__(self, as_user, credentials_map_file=None, refresh_interval=1):
        self.cred_manager = CredentialManager.instance(credentials_map_file)
        # as_user
        if as_user == '@':
            # No impersonation
            self.as_user = win32api.GetUserName()
        else:
            self.as_user = 'cloudrunner'  # self.cred.user
        self.refresh_interval = refresh_interval

    def get_home(self):
        return os.environ.get('HOME', "c:\\temp\\")

    def get_node(self):
        return os.environ.get('HOME', "c:\\temp\\")

    def get_uid(self):
        return winsec.LookupAccountName('', self.as_user)[0]

    def get_gid(self):
        return None

    def impersonate(self):
        if self.as_user != '@':
            cred = self.cred_manager.get_cred(self.as_user)
            self.handle = winsec.LogonUser(
                cred.username, cred.domain, cred.password,
                win32con.LOGON32_LOGON_INTERACTIVE,
                win32con.LOGON32_PROVIDER_DEFAULT)
            winsec.ImpersonateLoggedOnUser(self.handle)

    def revert(self):
        if self.as_user != '@':
            winsec.RevertToSelf()  # terminates impersonation
            self.handle.Close()  # guarantees cleanup

    def chmod(self, path, *modes):
        chmod(path, self.get_uid(), *modes)

    def chown(self, path, uid, gid):
        # we set permissions to user only, no need to change owner
        pass

    def popen(self, exec_file_args, session_cwd, env):
        # self.impersonate()
        try:
            proc = subprocess.Popen(exec_file_args,
                                    # Disable stdin until blocking is fixed
                                    # stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    cwd=session_cwd,
                                    env=env)
        except:
            raise
        else:
            return PopenWrapper(proc, self.as_user)
        finally:
            # Ensure revert is called
            # self.revert()
            pass


class PopenWrapper(object):
    STDIN = 1
    STDOUT = 2
    STDERR = 3
    TRANSPORT = 4

    def __init__(self, popen, run_as):
        self.popen = popen
        self.stdin = popen.stdin
        self.stdout = popen.stdout
        self.stderr = popen.stderr
        self.input = None
        self.run_as = run_as

        self.stdout_reader = AsyncPipeReader(self.stdout)
        self.stderr_reader = AsyncPipeReader(self.stderr)
        self.stdout_reader.start()
        self.stderr_reader.start()

    def set_input_sock(self, input_socket):
        self.input = input_socket

    def select(self, timeout=0):
        ret = []
        if self.input and self.input.poll(timeout):
            ret.append(self.TRANSPORT)

        if self.stdout_reader.has_data():
            ret.append(self.STDOUT)

        if self.stderr_reader.has_data():
            ret.append(self.STDERR)

        return ret

    def read_out(self):
        return self.stdout_reader.read()

    def read_err(self):
        return self.stderr_reader.read()

    def write(self, data):
        self.stdin.write(data)

    def finalize(self):
        stdout, stderr = '', ''
        try:
            try:
                if self.popen.poll() is None:
                    final_stdout, final_stderr = self.popen.communicate()
                    stdout = final_stdout
                    stderr = final_stderr
            except:
                pass

            ret_code = self.popen.returncode
            return (self.run_as, ret_code, stdout, stderr)
        finally:
            self.stdout_reader.close()
            self.stderr_reader.close()

    # override methods

    def poll(self):
        return self.popen.poll()

    def kill(self):
        return self.popen.kill()

    def terminate(self):
        return self.popen.terminate()
