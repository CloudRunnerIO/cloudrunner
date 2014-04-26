#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# PYTHON_ARGCOMPLETE_OK

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

from cloudrunner import CONFIG_NODE_LOCATION
from cloudrunner import NODE_LOG_LOCATION
from cloudrunner import LIB_DIR
from cloudrunner.util.cert_store import CertStore
from cloudrunner.util.loader import load_plugins
from cloudrunner.util.logconfig import configure_loggers
from cloudrunner.util.config import Config

CONFIG = Config(CONFIG_NODE_LOCATION)
if CONFIG.verbose_level:
    configure_loggers(getattr(logging, CONFIG.verbose_level, 'INFO'),
                      NODE_LOG_LOCATION)
else:
    configure_loggers(logging.DEBUG if CONFIG.verbose else logging.INFO,
                      NODE_LOG_LOCATION)

try:
    import argcomplete
except ImportError:
    pass
import argparse
import argparse
import json
import os
import signal
import socket
from threading import Thread
from threading import Event
import time
import sys

from cloudrunner.core import parser
from cloudrunner.core.exceptions import ConnectionError
from cloudrunner.core.message import RegisterRep
from cloudrunner.core.message import ADMIN_TOWER
from cloudrunner.core.message import StatusCodes
from cloudrunner.core.process import Processor
from cloudrunner.node.matcher import Matcher
from cloudrunner.plugins.transport.base import TransportBackend
from cloudrunner.util.daemon import Daemon
from cloudrunner.util.loader import load_plugins
from cloudrunner.util.loader import load_plugins_from
from cloudrunner.util.shell import colors
from cloudrunner.util.validator import validate_address

LOG = logging.getLogger('Node Daemon')


class AgentNode(Daemon):

    def __init__(self):
        super(Daemon, self).__init__()

        self._parser = _parser()
        try:
            argcomplete.autocomplete(self._parser)
        except:
            pass

        self.args = self._parser.parse_args()

        if 'NO_COLORS' in os.environ:
            colors.disable()

        # Defaults to Single-user transport
        transport_class = CONFIG.transport or \
            'cloudrunner.plugins.transport.node_transport.NodeTransport'

        (mod, _, klass) = transport_class.rpartition('.')
        self.transport_class = None
        transport_module = load_plugins_from(mod, [TransportBackend])
        if not transport_module:
            print colors.red("Cannot find module for transport plugin: %s" %
                             mod)
            exit(1)
        for _klass in transport_module:
            if _klass.__name__ == klass:
                self.transport_class = _klass
                break

        if not self.transport_class:
            print colors.red("Cannot find transport class %s from module %s" %
                            (klass, mod))
            exit(1)

        assert self.transport_class
        load_plugins(CONFIG)

    def choose(self):
        if self.args.action in ['start', 'stop', 'restart']:
            if not self.args.pidfile:
                print colors.red("The --pidfile option is required"
                                 " with [start, stop, restart] commands",
                                 bold=1)
                exit(1)
            super(AgentNode, self).__init__(self.args.pidfile)

        getattr(self, self.args.action, 'run')()

    def configure(self):
        # Run initial configuration
        LOG.info("Running initial configuration")
        self.backend = self.transport_class.from_config(
            CONFIG, **vars(self.args))
        kwargs = dict(vars(self.args))
        if "overwrite" in kwargs:
            kwargs.pop("overwrite")
        self.backend.configure(overwrite=self.args.overwrite, **kwargs)

    def details(self):
        self.matcher = Matcher(CONFIG.node_id)
        props = [(k, v) for (k, v) in self.matcher.props.items()]
        props = sorted(props, key=lambda x: x[0])
        print colors.blue('%-30s' % 'ID', bold=1), colors.blue('%s' %
                                                               CONFIG.node_id)
        for item in props:
            print colors.blue('%-30s' % item[0], bold=1), colors.blue(item[1])
        if not hasattr(self, "backend"):
            self.backend = self.transport_class.from_config(CONFIG)
        if self.backend.properties:
            print colors.blue('===== Backend properties =====')
            for item in self.backend.properties:
                print colors.blue('%-30s' % item[0], bold=1), \
                    colors.blue(item[1])

    def register_cli(self):
        user_store = CONFIG.user_store
        store = CertStore(user_store)
        if not store.insert(self.args.common_name, self.args.fingerprint):
            exit(2)

    def list_cli(self):
        user_store = CONFIG.user_store
        store = CertStore(user_store)
        for cli in store._store:
            print colors.blue("%-40s %s" % cli)

    def unregister_cli(self):
        user_store = CONFIG.user_store
        store = CertStore(user_store)
        if not store.remove(common_name=self.args.common_name,
                            fingerprint=self.args.fingerprint):
            exit(2)

    def run(self):
        """
        Main method of CloudRunner node.
        It tries to register if not registered yet.
        """
        self.node_id = CONFIG.node_id
        self.running = Event()
        if CONFIG.mode == "server" and (not CONFIG.master_pub or
                                        not CONFIG.master_repl):
            print colors.yellow("Master IP:port is not set in config file (%s)"
                                % CONFIG._fn)
            master_pub = raw_input("Enter Master PUB uri (IP or IP:port):")
            if ":" in master_pub:
                ip, _, port = master_pub.rpartition(":")
            else:
                ip = master_pub
                port = 5551
            CONFIG.update("General", "master_pub", "%s:%s" % (ip,
                                                              port))
            master_repl = raw_input("Enter Master REPLY uri (IP or IP:port), "
                                    "hit ENTER for default(%s:5552):" % ip)
            if not master_repl:
                port = 5552
            elif ":" in master_repl:
                ip, _, port = master_repl.rpartition(":")
            else:
                ip = master_repl
                port = 5552
            CONFIG.update("General", "master_repl", "%s:%s" % (ip,
                                                               port))
            CONFIG.reload()

            if not validate_address(CONFIG.master_pub) or \
                    not validate_address(CONFIG.master_repl):
                LOG.error('Server IP not present in config or is not valid.\n'
                          'Check your config')
                exit(1)

        if not self.node_id:
            LOG.error("The node id not set in config. "
                      "Run program with config option first")
            exit(1)

        self.matcher = Matcher(self.node_id)
        self.backend = self.transport_class.from_config(
            CONFIG, **vars(self.args))
        load_plugins(CONFIG)
        self.sessions = {}

        LOG.info("Starting node")
        self.details()
        self._sig_int = signal.getsignal(signal.SIGINT)
        self._sig_term = signal.getsignal(signal.SIGTERM)

        if os.name == 'nt':
            # Use Ctrl+C to invoke clean on Windows
            import win32api
            win32api.SetConsoleCtrlHandler(self.clean, True)
        else:
            signal.signal(signal.SIGINT, self._handle_terminate)
            signal.signal(signal.SIGTERM, self._handle_terminate)

            # Invoke clean for sessions
            signal.signal(signal.SIGHUP, self.clean)

        if not self.backend.prepare():
            LOG.info("Cannot start transport backend")
            self._handle_terminate()
            exit(1)

        def request_processor():
            req_queue = self.backend.consume_queue('requests')
            poller = self.backend.create_poller(req_queue)
            while not self.running.is_set():
                try:
                    ready = poller.poll(200)
                    if not ready:
                        continue
                    if req_queue in ready:
                        message = req_queue.recv()
                        if not message:
                            continue
                        self.target_match(*message)
                except ConnectionError:
                    break
            req_queue.close()

        Thread(target=request_processor).start()

        self.backend.loop()

        LOG.info("Node exited")

    def _handle_terminate(self, *args):
        self.running.set()
        signal.signal(signal.SIGINT, self._sig_int)
        signal.signal(signal.SIGTERM, self._sig_term)
        LOG.info("Exiting Node, current sessions: %s" % self.sessions)
        self.backend.terminate()

    class Dispatcher(Thread):

        def __init__(self, backend):
            control_queue = backend.publish_queue('dispatcher')
            super(AgentNode.Dispatcher, self).__init__()

        def run(self):
            pass

    class Session(Thread):

        def __init__(self, session_id, backend):
            super(AgentNode.Session, self).__init__()
            self.session_id = str(session_id)
            self.done = False
            self.backend = backend
            self.queue = backend.publish_queue('jobs', ident=self.session_id)
            self.queue.send(self.session_id, StatusCodes.READY)

            LOG.info("Creating session %s" % self.session_id)

        def _close(self):
            self.done = True
            self.queue.close()

        def term(self):
            self._close()

        def kill(self):
            self._close()

        def _yield_reply(self, *reply):
            LOG.debug("[%s] Yielding %s" % (self.session_id, reply[0]))
            try:
                self.queue.send(self.session_id, *list(reply))
            except ConnectionError:
                self._close()

        def run(self):
            self.job_attr = self.queue.recv(2)
            if not self.job_attr:
                LOG.error("[%s] Timeout waiting for Job description" %
                          self.session_id)
                self._close()
                return
            command = self.job_attr[0].lower()
            if not hasattr(self, command):
                LOG.error('Session %s: UNKNOWN COMMAND RECEIVED:: %s' % (
                    self.session_id, command))
                return

            LOG.info("Session::%s: command:: %s" % (self.session_id, command))

            return getattr(self, command)(*self.job_attr[1:])

        def job(self, *args):
            LOG.info('Recv:: JOB for session %s', self.session_id)
            try:
                remote_user, request = json.loads(args[0])
            except ValueError:
                LOG.error('Malformed request received: %s' % args[0])
                return
            command = request['script']
            env = request['env']
            proc = Processor(remote_user)
            lang = parser.parse_lang(command)

            LOG.info("Node[%s]::: User:::[%s] UUID:::[%s] LANG:::[%s]" %
                     (CONFIG.node_id, remote_user, self.session_id, lang))

            if isinstance(command, unicode):
                command = command.encode('utf8')

            incl_header = []

            libs = request.get('libs', [])
            if libs:
                for lib in libs:
                    # Save libs if any
                    script = proc.add_libs(**lib)
                    if script:
                        # inline
                        if isinstance(script, unicode):
                            script = script.encode('utf8')
                        incl_header.append(script)
            # For long-running jobs
            # self.socket.send_multipart([self.session_id,
            #                            StatusCodes.WORKING,
            #                            json.dumps(dict(stdout=value))])

            proc_iter = iter(proc.run(command, lang, env, inlines=incl_header))
            proc = next(proc_iter)

            if not isinstance(proc, list):
                proc.set_input_fd(self.queue)

                running = True
                while running:
                    to_read = proc.select(.2)
                    if proc.poll() is not None:
                        # We are done with the task
                        LOG.info("Job %s finished" % self.session_id)
                        running = False
                        # Do not break, let consume the streams
                    for fd_type in to_read:
                        if fd_type == proc.TRANSPORT:
                            try:
                                frames = self.queue.recv(0)
                            except:
                                continue
                            if frames and len(frames) == 2:
                                if frames[0] == 'INPUT':
                                    try:
                                        proc.write(frames[1])
                                    except:
                                        continue
                                elif frames[0] == 'TERM':
                                    if len(frames) > 1 and frames[1] == 'kill':
                                        # kill task
                                        proc.kill()
                                        LOG.info("Job %s killed" %
                                                 self.session_id)
                                    else:
                                        # terminate task
                                        proc.terminate()
                                        LOG.info("Job %s terminated" %
                                                 self.session_id)
                                    continue
                        if fd_type == proc.STDOUT:
                            data = proc.read_out()
                            if data:
                                self._yield_reply(
                                    StatusCodes.STDOUT,
                                    proc.run_as,
                                    json.dumps(dict(stdout=data)))
                        if fd_type == proc.STDERR:
                            data = proc.read_err()
                            if data:
                                self._yield_reply(
                                    StatusCodes.STDERR,
                                    proc.run_as,
                                    json.dumps(dict(stderr=data)))

                run_as, ret_code, stdout, stderr, env = next(proc_iter)
            else:
                # Error invoking Popen, get params
                run_as, ret_code, stdout, stderr, env = proc
                if stdout:
                    self._yield_reply(StatusCodes.STDOUT,
                                      run_as,
                                      json.dumps(dict(stdout=stdout)))
                if stderr:
                    self._yield_reply(StatusCodes.STDERR,
                                      run_as,
                                      json.dumps(dict(stderr=stderr)))

            job_result = json.dumps(dict(env=env,
                                         ret_code=ret_code,
                                         stdout=stdout, stderr=stderr))
            LOG.info('Job [%s] DONE' % (self.session_id))
            self._yield_reply(StatusCodes.FINISHED, run_as, job_result)

            self._close()
            # Invoke clean
            if os.name == 'nt':
                import win32api
                import win32con
                win32api.GenerateConsoleCtrlEvent(win32con.CTRL_C_EVENT, 0)
            else:
                os.kill(os.getpid(), signal.SIGHUP)

        def ack(self, *args):
            LOG.info("Session::%s :: ACK" % self.session_id)
            self._close()

        def err(self, *args):
            LOG.info("Session::%s :: ERR:: %s" % (self.session_id, args))
            self._close()

    def target_match(self, *args):
        session_id, targets = args[0], args[1]
        if self.matcher.is_match(targets):
            try:
                session = AgentNode.Session(session_id, self.backend)
                session.start()
                self.sessions[session_id] = session
                return True
            except Exception, ex:
                LOG.error("Cannot start Job Session: %r" % ex)
        return False

    def clean(self, *args):
        if os.name == 'nt':
            LOG.info("Cleaning finished sessions")
        else:
            LOG.debug("Cleaning finished sessions")
        for k in self.sessions.keys():
            # Clear done
            if self.sessions[k].done:
                self.sessions.pop(k)


def _parser():
    parser = argparse.ArgumentParser(
        description="CloudRunner Node tool",
        formatter_class=argparse.RawTextHelpFormatter)

    actions = parser.add_subparsers(dest="action",
                                    help='Apply action on the daemonized process\n'
                                    'For the actions [start, stop, restart] - pass a pid file\n'
                                    'Configure - performs initial configuration\n'
                                    'Run - start process in debug mode\n')

    _common_run = argparse.ArgumentParser(add_help=False)

    _common_run.add_argument('-w', '--wait-for', default=5,
                                   dest='wait_for_approval',
                                   help='Wait the specified seconds for '
                             'approval from Master.\n'
                             '0 means don\'t wait but exit.'
                             'Default is %(default)s.')

    _common_run.add_argument('-p', '--pidfile', dest='pidfile',
                             help='Daemonize process with the '
                                  'given pid file')

    _common_run.add_argument('-d', '--var_dir', dest='var_dir',
                             required=False,
                             help='Default directory to store '
                                  'configuration\nDefaults to %s' % LIB_DIR)

    actions.add_parser('start', parents=[_common_run])
    actions.add_parser('stop', parents=[_common_run])
    actions.add_parser('restart', parents=[_common_run])
    actions.add_parser('run', parents=[_common_run])
    actions.add_parser('details',)

    configure = actions.add_parser('configure')
    configure.add_argument('-o', '--overwrite', action='store_true',
                           default=False,
                           help='When running initial configuration or '
                           'performing re-configuration -\n'
                           'overwrite the existing credentials.\n'
                           'Use with caution!')

    configure.add_argument('-i', '--id', dest='node_id',
                           required=False,
                           help='When running configuration -\n'
                           'manually set the node ID.')

    configure.add_argument('--org', dest='org',
                           required=False,
                           help='Organization to be set in certificate')

    configure.add_argument('--server', dest='server_uri',
                           required=False,
                           help='Remove Server IP address')

    configure.add_argument('-k', '--key-size', default=2048,
                           help='Default size of Node key. '
                           'Default is %(default)s',
                           required=False)

    if (CONFIG.user_store):
        register_cli = actions.add_parser('register_cli')
        register_cli.add_argument('-cn', '--common-name',
                                  required=True,
                                  help='Common name of the certificate'
                                  ' to be used, as listed in subject. Use:\n'
                                  '\tcloudrunner-exec details\n'
                                  'to find the fingerprint')

        register_cli.add_argument('-fp', '--fingerprint',
                                  required=True,
                                  help='Fingerprint of the certificate'
                                  ' to be used. Use:\n'
                                  '\tcloudrunner-exec details\n'
                                  'to find the fingerprint')

        unregister_cli = actions.add_parser('unregister_cli')
        unregister_cli.add_argument('-cn', '--common-name',
                                    help='Common name of the certificate'
                                    'to be removed as listed in subject. Use:\n'
                                    '\tcloudrunner-exec details\n'
                                    'to find the fingerprint')

        unregister_cli.add_argument('-fp', '--fingerprint',
                                    help='Fingerprint of the certificate'
                                    ' to be removed. Use:\n'
                                    '\tcloudrunner-exec details\n'
                                    'to find the fingerprint')

        list_cli = actions.add_parser('list_cli')

    return parser


def main():
    node = AgentNode()
    node.choose()

if __name__ == "__main__":
    main()
