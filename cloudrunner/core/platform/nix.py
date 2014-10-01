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
import os
import pwd
import select
import stat
from StringIO import StringIO
from subprocess import Popen
from subprocess import PIPE

MOD_MAP = {
    # Owner
    'IR': stat.S_IRUSR,
    'IW': stat.S_IWUSR,
    'IE': stat.S_IXUSR,
    # Group
    'GR': stat.S_IRGRP,
    'GW': stat.S_IWGRP,
    'GE': stat.S_IXGRP,
    # Other
    'OR': stat.S_IROTH,
    'OW': stat.S_IWOTH,
    'OE': stat.S_IXOTH,
}

LOG = logging.getLogger("NixProcessor")


class NixProcessor(object):

    def __init__(self, as_user, refresh_interval=1):
        self.refresh_interval = refresh_interval

        try:
            if as_user == '@':
                # No impersonation

                self.user = pwd.getpwuid(os.getuid())
                self.as_user = self.user[0]
            else:
                self.user = pwd.getpwnam(as_user)
                self.as_user = as_user
            self.ready = True
        except Exception, ex:
            LOG.error(ex)
            LOG.warn("Cannot find local user %s" % as_user)
            self.ready = False

    def get_home(self):
        return self.user.pw_dir

    def get_uid(self):
        return self.user.pw_uid

    def get_gid(self):
        return self.user.pw_gid

    def impersonate(self):
        os.setgid(self.user.pw_gid)
        os.setuid(self.user.pw_uid)

    @staticmethod
    def chmod(path, *modes):
        mode = 0
        for m in modes:
            mode |= MOD_MAP[m]
        try:
            os.chmod(path, mode)
        except Exception, ex:
            LOG.exception(ex)

    @staticmethod
    def chown(path, uid, gid):
        try:
            os.chown(path, uid, gid)
        except Exception, ex:
            LOG.warning(str(ex))

    def popen(self, exec_file_name, session_cwd, env):
        proc = Popen(exec_file_name,
                     shell=True,
                     stdin=PIPE,
                     stdout=PIPE,
                     stderr=PIPE,
                     preexec_fn=self.impersonate,
                     cwd=session_cwd,
                     env=env,
                     bufsize=0)

        return PopenWrapper(proc, self.as_user)


class PopenWrapper(object):
    STDOUT = 2
    STDERR = 3
    TRANSPORT = 4

    def __init__(self, popen, run_as):
        self.popen = popen
        self.stdin = popen.stdin
        self.stdout = popen.stdout
        self.stderr = popen.stderr
        self.stdout_fd = self.stdout.fileno()
        self.stderr_fd = self.stderr.fileno()
        self.input_fd = None
        self.run_as = run_as

    def set_input_fd(self, input_socket):
        self.input_fd = input_socket.fd()

    def select(self, timeout=0):
        socks = [self.stdout_fd, self.stderr_fd]
        if self.input_fd:
            socks.append(self.input_fd)
        to_read, _, __ = select.select(socks, [], [], timeout)

        ret = []
        if self.stdout_fd in to_read:
            ret.append(self.STDOUT)
        if self.stderr_fd in to_read:
            ret.append(self.STDERR)
        if self.input_fd and self.input_fd in to_read:
            ret.append(self.TRANSPORT)
        return ret

    def read_out(self):
        buf = StringIO()
        while True:
            data = os.read(self.stdout_fd, 4096)
            if data:
                buf.write(data)
            if len(data) < 4096:
                break

        return buf.getvalue()

    def read_err(self):
        buf = StringIO()
        while True:
            data = os.read(self.stderr_fd, 4096)
            if data:
                buf.write(data)
            if len(data) < 4096:
                break

        return buf.getvalue()

    def write(self, data):
        self.stdin.write(data)

    def finalize(self):
        stdout, stderr = '', ''
        try:
            if self.popen.poll() is None:
                # running yet?
                final_stdout, final_stderr = self.popen.communicate()
                stdout = final_stdout
                stderr = final_stderr
        except:
            pass

        ret_code = self.popen.returncode

        return (ret_code, stdout, stderr)

    # override methods

    def poll(self):
        return self.popen.poll()

    def kill(self):
        return self.popen.kill()

    def terminate(self):
        return self.popen.terminate()
