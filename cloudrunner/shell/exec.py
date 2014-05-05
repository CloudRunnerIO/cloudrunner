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

try:
    import argcomplete
except ImportError:
    pass
import argparse
import errno
import json
import logging
import os
from select import select
from select import error as sel_err
import socket
import sys

from cloudrunner import CONFIG_SHELL_LOC
from cloudrunner import LIB_DIR
from cloudrunner.core import message
from cloudrunner.core import parser
from cloudrunner.core.message import StatusCodes
from cloudrunner.util.config import Config
from cloudrunner.util.loader import load_plugins
from cloudrunner.util.loader import local_plugin_loader
from cloudrunner.util.logconfig import configure_loggers
from cloudrunner.util.shell import colors
from cloudrunner.util.shell import Console
from cloudrunner.util.http import load_from_link
from cloudrunner.util.http import parse_url

from cloudrunner.core.exceptions import Unauthorized

CONFIG = Config(CONFIG_SHELL_LOC)
PLUGINS = {}

LOG_FORMAT = '! %(levelname)s:%(message)s'

configure_loggers(CONFIG.verbose_level or logging.INFO,
                  CONFIG.log_file or LIB_DIR + 'cloudrunner-node.log',
                  log_format=LOG_FORMAT)

LOG = logging.getLogger('ShellRunner')
DEFAULT_TIMEOUT = 60
console = Console()


class Exit(Exception):
    pass


class ShellRunner(object):

    """
        Base class to split and send scripts to CloudRunner Dispatcher
    """

    def __init__(self, *args, **kwargs):

        self._parser = _parser()

        try:
            argcomplete.autocomplete(self._parser)
        except:
            pass

        if args:
            self.args = self._parser.parse_args(args)
        else:
            self.args = self._parser.parse_args()

        if self.args.config:
            global CONFIG
            CONFIG = Config(self.args.config)

        if 'verbose' in self.args and self.args.verbose:
            configure_loggers(logging.DEBUG,
                              CONFIG.log_file or
                              LIB_DIR + 'cloudrunner-node.log')
            self.kwargs = kwargs

    def choose(self):
        shell = Shell(args=self.args)

        if not hasattr(shell, self.args.controller):
            if self.args.controller in PLUGINS:
                plugin_cmd = PLUGINS[self.args.controller]
                getattr(shell, plugin_cmd)()
            else:
                console.red("Unrecognized command: ", self.args.controller)
        else:
            getattr(shell, self.args.controller)()


def needs_config(func):
    def set_config(self, *args, **kwargs):
        to_exit = True
        if 'no_exit' in kwargs:
            kwargs.pop('no_exit')
            to_exit = False
        self._setup()
        try:
            return func(self, *args, **kwargs)
        except Unauthorized:
            req_user = self.args.user or self.kwargs.get("CLOUDRUNNER_USER")
            console.red("Remote server: Access denied for user %s" % req_user)
            self.close(force=True)
            if to_exit:
                exit(1)
            else:
                return []
        except Exit:
            self.close(force=True)
            if to_exit:
                exit(1)
            else:
                return []
        finally:
            self.close()
    return set_config


class ArgsWrapper(object):

    def __init__(self, **args):
        for arg in args.keys():
            setattr(self, arg, args[arg])

    def __contains__(self, key):
        return hasattr(self, key)


class Shell(object):

    def __init__(self, *args, **kwargs):

        kwargs.update(
            {'auth_user': os.environ.get('CLOUDRUNNER_USER'),
             'auth_token': os.environ.get('CLOUDRUNNER_TOKEN'),
             'dispatcher_uri': os.environ.get('CLOUDRUNNER_SERVER')})

        if "args" in kwargs:
            self.args = kwargs.pop('args')
        else:
            self.args = ArgsWrapper(**kwargs)

        self.kwargs = kwargs

        if 'stdout' in kwargs:
            sys.stdout = kwargs['stdout']
            sys.stderr = kwargs['stdout']

        if 'no_colors' in kwargs:
            colors.disable()

        if 'NO_COLORS' in os.environ:
            colors.disable()

    def _create_backend(self):
        transport = CONFIG.transport_class or \
            'cloudrunner.plugins.transport.zmq_transport.ZmqCliTransport'
        transport_class = local_plugin_loader(transport)
        if not transport_class:
            console.red("Cannot instantiate transport class: %s",
                        transport)
            exit(1)

        self.backend = transport_class.from_config(CONFIG, **self.kwargs)

    def _setup(self):
        """
        Perform initial confiiguration
        """
        self._create_backend()
        self.backend.prepare()

        self.queue = self.backend.publish_queue('requests')
        self.renderer = ResultPrinter(self.queue)

        load_plugins(CONFIG)

        if 'timeout' in self.args:
            # override timeout from args?
            try:
                self.timeout = int(self.args.timeout)
            except:  # invalid timeout
                self.timeout = DEFAULT_TIMEOUT

    def _script(self, tgt='script', ignore=False):
        _script = getattr(self.args, tgt, None)
        if not _script and ignore:
            return ""
        if not self.args.inline:
            if ignore:
                return ""

            if not _script:
                console.red("Script not provided. "
                            "Use --help to see options")
                exit(1)

            is_link = parse_url(_script)
            if is_link:
                proto_host = is_link[0]
                file_name = is_link[1]
                console.blue("Loading script", file_name,
                             "from", proto_host)
                kwargs = {}
                if self.args.auth_remotely:
                    kwargs['auth_user'] = self.args.user
                    kwargs['auth_token'] = self.args.token
                status, script_content = load_from_link(proto_host, file_name,
                                                        **kwargs)
                if status != 0:
                    console.red("Error reading script from address.",
                                "Server returned code:", status, script)
                    exit(1)
            elif not os.path.exists(_script):
                console.red("Script %s doesn't exist" % _script)
                exit(1)
            else:
                script_content = open(_script).read()
        else:
            if _script:
                script_content = _script
            else:
                console.blue("Enter script, Ctrl+D for end:")
                try:
                    script_content = "\n".join(sys.stdin.readlines())
                except KeyboardInterrupt:
                    console.blue("Exiting...")
                    sys.exit(0)

        if isinstance(script_content, unicode):
            script_content = script_content.encode('utf8')

        return script_content

    def details(self):
        self._create_backend()
        if self.backend.properties:
            for item in self.backend.properties:
                print colors.blue('%-30s' % item[0], bold=1), \
                    colors.blue(item[1])

    def configure(self):

        # Do cli config

        # Do backend config
        self._create_backend()
        self.backend.configure(overwrite=self.args.overwrite)

    def mode(self):
        if self.args.mode:
            CONFIG.update('General', 'mode', self.args.mode)
            CONFIG.reload()

    def list_nodes_get(self, command):
        req = self._request()
        req.append(control=command)
        result = []

        self.queue.send(*req.pack())
        success, resp = self.queue.recv(timeout=5)
        try:
            result = json.loads(resp)
        except:
            console.red('Error: ', resp)
            exit(1)

        return result

    @needs_config
    def list_nodes(self):
        result = self.list_nodes_get('list_nodes')
        if not result[0]:
            console.red("Error getting nodes on Master", result, bold=1)
            return

        console.green("=" * 80)
        console.green("Available nodes on Master", bold=1)
        console.green("=" * 80)

        for node in result[1]:
            console.blue(node)

    @needs_config
    def list_active_nodes(self):
        result = self.list_nodes_get('list_active_nodes')
        if not result[0]:
            console.red("Error getting nodes on Master", result, bold=1)
            return

        console.green("=" * 80)
        console.green("Available nodes on Master", bold=1)
        console.green("=" * 80)

        for node in result[1]:
            console.blue(node)

    @needs_config
    def list_pending_nodes(self):
        result = self.list_nodes_get('list_pending_nodes')
        if not result[0]:
            console.red("Error getting nodes on Master", result, bold=1)
            return

        console.green("=" * 80)
        console.green("Pending nodes on Master", bold=1)
        console.green("=" * 80)

        for node in result[1]:
            console.blue(node)

    @needs_config
    def plugins_get(self, *ar):

        req = self._request()

        req.append(control='plugins')

        result = []

        self.queue.send(*req.pack())
        resp = self.queue.recv(timeout=3)
        if not resp:
            console.red('Cannot connect to server %s' %
                        self.backend.dispatcher_uri)
            raise Exit()

        if len(resp) > 1:
            result = json.loads(resp[1])
        else:
            console.red('Error: ', resp[0])
            exit(1)

        return result

    def plugins(self):
        result = self.plugins_get()

        console.green("=" * 80)
        console.green("Plugins available on Master", bold=1)
        console.green("=" * 80)

        console.new_line()

        console.green('*' * 3, "Job Plugins", '*' * 3)
        for arg in result[0]:
            console.blue(arg[0])
            console.yellow('\t' + '\n\t'.join(arg[1]))

        console.new_line()
        console.green('*' * 3, "CLI Plugins", '*' * 3)
        console.blue(result[1][0])
        console.yellow('\t' + '\n\t'.join(result[1][1]))

    @needs_config
    def plugin_get(self):
        req = self._request()
        req.append(plugin=self.args.controller)

        req.append(control='plugin', data=self._script(ignore=True))

        req.append(args='"' + '" "'.join(self.args.xargs) + '"')

        self.queue.send(*req.pack())
        resp = self.queue.recv(timeout=5)
        if not resp:
            console.red('Cannot connect to server')
            raise Exit()

        if len(resp) > 1:
            return json.loads(resp[1])
        else:
            console.red('Error: ', resp[0])
            return ""

    def plugin(self):

        result = self.plugin_get()

        console.green("=" * 80)
        console.green("Result from plugin run:", bold=1)
        console.green("=" * 80)

        if result:
            for res in result:
                success, msg = res
                if success:
                    console.blue(msg)
                else:
                    console.red(msg)
        else:
            console.red('Error: %s' % result)

    def capture_run(self):
        colors.disable()
        from StringIO import StringIO
        log_to = StringIO()
        _stdout = sys.stdout
        _stderr = sys.stderr
        sys.stdout = log_to
        sys.stderr = log_to

        try:
            self.run()
        except:
            return False
        finally:
            sys.stdout = _stdout
            sys.stderr = _stderr
        return log_to.getvalue()

    def attach(self):
        req = self._request()
        req.append(control='attach')

        req.append(data=json.dumps(self.args.targets))
        req.append(session_id=self.args.session_id)
        # we do not know the original timeout,
        self.timeout = sys.maxint / 1000

        self.queue.send(*req.pack())
        r = self.queue.recv(timeout=5)
        status, resp = r

        if len(r) != 2:
            console.red('Error: ', r[0])
            exit(2)

            self.renderer.out(status, resp)

    def notify(self, session_id=None, job_id=None, data=None, targets=None,
               to_read=True):
        req = self._request()
        req.append(control='notify')

        req.append(data=data or self._script(tgt='input'))
        req.append(targets=targets or json.dumps(self.args.targets))
        req.append(session_id=session_id or self.args.session_id)
        req.append(job_id=job_id or self.args.job_id)

        self.queue.send(*req.pack())

        if not to_read:
            return

        resp = self.queue.recv(timeout=5)

        if not resp:
            console.red('Cannot connect to server')
            raise Exit()

        status, r = resp

        if len(r) != 2:
            console.red('Error: ', r[0])
            exit(2)

        console.blue(r[1])

    def terminate(self, sess, sig=None, to_read=True):
        req = self._request()
        req.append(control='term')

        req.append(session_id=sess or self.args.session_id)
        req.append(action=sig or ('kill' if self.args.kill else 'term'))

        self.queue.send(*req.pack())

        if not to_read:
            return

        r = self.queue.recv(timeout=5)
        status, resp = r

        if len(r) != 2:
            console.red('Error: ', r[0])
            exit(2)

        reply = json.loads(resp)
        if reply[0]:
            console.blue(reply[1])
        else:
            console.red(reply[1])

    def peers(self):
        self._create_backend()
        if self.args.task == 'list':
            # List peers
            for peer in self.backend.peer_store._store:
                console.yellow("%-40s %s" % peer)
        if self.args.task == 'delete':
            self.backend.peer_store.remove(common_name=self.args.name)

    def hosts(self):
        self._create_backend()
        if self.args.task == 'list':
            # List hosts
            mappings = self.backend.host_resolver.mappings()
            for target, hosts in mappings.items():
                console.green("[%s]" % target, bold=1)
                for host in hosts:
                    console.yellow("%-20s" % host)
        if self.args.task == 'add':
            self.backend.host_resolver.add(self.args.mapping,
                                           self.args.name, self.args.host)
        if self.args.task == 'delete':
            if not self.backend.host_resolver.remove(self.args.mapping,
                                                     self.args.host):
                console.red("Not removed")

    @needs_config
    def run(self, detach=False):
        req = self._request()

        script_content = self._script()

        req.append(control='dispatch')

        includes = self._includes()
        if includes:
            req.append(includes=includes)

        if self.args.env:
            try:
                self.env = json.loads(self.args.env)
            except Exception, ex:
                LOG.exception(ex)
                exit(1)
        else:
            self.env = {}

        if CONFIG.mode == "server":
            if self.args.tags:
                req.append(tags=self.args.tags)

            if self.args.name:
                req.append(caller=self.args.name)

            if self.args.test:
                req.append(test=True)

        req.append(timeout=self.timeout)

        script_content = parser.CRN_SHEBANG.sub("", script_content)

        sections = parser.split_sections(script_content)
        if not sections:
            return

        first_section = sections[0]
        if not parser.parse_selectors(first_section.strip())[0]:
            if first_section.strip():  # has content?
                # Local run
                console.green("=" * 80)
                console.green("Running local script", bold=1)
                console.green("=" * 80)
                from cloudrunner.core.process import Processor
                processor = Processor("@")
                lang = parser.parse_lang(first_section)
                proc_iter = iter(processor.run(first_section, lang, self.env))
                proc = next(proc_iter)
                if not isinstance(proc, list):
                    while True:
                        try:
                            to_read = proc.select(.2)
                            if proc.poll() is not None:
                                # We are done with the task
                                break
                            for fd_type in to_read:
                                if fd_type == proc.STDOUT:
                                    data = proc.read_out()
                                    if data:
                                        console.log(data)
                                if fd_type == proc.STDERR:
                                    data = proc.read_err()
                                    if data:
                                        console.red(data)
                        except KeyboardInterrupt:
                            console.log("Exiting")
                            break
                    run_as, ret_code, stdout, stderr, env = next(proc_iter)
                else:
                    run_as, ret_code, stdout, stderr, env = proc

                if stdout:
                    console.log(stdout)
                if stderr:
                    console.red(stderr)

                console.yellow("=" * 80)
                console.yellow("Exit code:", ret_code)
                console.yellow("=" * 80)
                env.update(self.env)
                self.env = env

        sections = "".join(sections[1:])

        req.append(data=sections)
        if self.env:
            req.append(env=self.env)

        self.queue.send(*req.pack())
        if not detach:
            console.green("=" * 80)
            console.green("Remote execution", bold=1)
            console.green("=" * 80)

            session_id = None
            self.renderer.capture(notify=self.notify,
                                  terminate=self.terminate)
        else:
            # Grab only job id and return
            r = self.queue.recv(timeout=5)
            job_id = None
            if r[0] == 'FINISHED':
                job_id = json.loads(r[1])[0]['jobid']
            if r[0] == 'PIPEOUT':
                job_id = json.loads(r[1])[0]

            return job_id
        self.close()

    def close(self, force=True):
        self.backend.terminate(force=True)

    def _request(self):
        if CONFIG.mode == "server":
            req_user = self.args.user or self.kwargs.get("CLOUDRUNNER_USER")
            req_token = self.args.token or self.kwargs.get("CLOUDRUNNER_TOKEN")
            if not req_user or not req_token:
                console.red("Username/token not found")
                exit(1)
        else:
            req_user = ""
            req_token = ""
        _req = message.AgentReq(login=req_user,
                                password=req_token)
        return _req

    def _includes(self):
        if not self.args.include:
            return []
        arr = []

        def _append(_list, elem):
            _list.extend(elem.split(';'))
            return _list
        reduce(_append, self.args.include, arr)
        libs = []
        for incl in arr:
            try:
                data = {}
                with open(incl) as f:
                    incl_content = f.read()
                    data["name"] = incl
                    data["source"] = incl_content
                    libs.append(data)
            except IOError:
                console.red("Cannot open include file %s" % incl)
        return libs


class ResultPrinter(object):

    def __init__(self, msg_queue):
        self.msg_queue = msg_queue
        self.running = True
        self.last_line, self.last_node = None, None

    def unpack(self, count, frames):
        l = list(frames[:count])
        l.append(frames[count:])
        return l

    def capture(self, notify, terminate):
        self.session_id = None
        self.job_id = None
        sock_fd = self.msg_queue.fd()

        def parse_result(sock):
            for r in sock.recv_nb():
                if not r:
                    continue
                try:
                    r_type, data = self.unpack(1, r)
                    self.session_id = data[0]
                except:
                    console.red('Error: ', r)
                    exit(2)

                self.out(r_type, data)
                if r_type == "PIPEOUT":
                    self.job_id = data[6]

        while self.running:
            try:
                try:
                    ready = select([sock_fd], [], [], 1)[0]
                except sel_err, err:
                    if err[0] != errno.EINTR:
                        raise
                    ready = {}
                if sock_fd in ready:
                    parse_result(self.msg_queue)

            except KeyboardInterrupt:
                console.green("\nChoose exit option:")
                if self.session_id:
                    console.green("\t[s]end input data for remote process\n"
                                  "\t[t]erminate the remote process(es) [SIGTERM]\n"
                                  "\t[k]ill the remote process(es) [SIGKILL]\n"
                                  "\t[c]ontinue execution or [e]xit the program")
                choice = None
                try:
                    choice = raw_input()
                except KeyboardInterrupt:
                    choice = "E"
                if self.session_id and choice in ['s', 'S']:
                    print "Enter targets(Hit Enter for all):"
                    targets = sys.stdin.readline()
                    if not targets.strip():
                        # all
                        targets = '*'
                    print "Enter input data(Ctrl+D for end):"
                    data = ''.join(sys.stdin.readlines())
                    notify(
                        self.session_id, self.job_id, data, targets,
                        to_read=False)
                    parse_result(self.msg_queue)
                elif choice in ['t', 'T']:
                    terminate(self.session_id, sig='term', to_read=False)
                    parse_result(self.msg_queue)
                elif choice in ['k', 'K']:
                    terminate(self.session_id, sig='kill', to_read=False)
                    parse_result(self.msg_queue)
                else:
                    self.running = False
                    console.blue("Good bye!")
        return

    def out(self, rtype, resp):
        if rtype in StatusCodes.pending():
            if len(resp) == 14:
                self.print_header(*resp)
            else:
                self.print_partial(*resp)
        elif rtype == StatusCodes.FINISHED:
            try:
                data = json.loads(resp[7])
                if isinstance(data, basestring):
                    data = json.loads(data)
                self.print_final(data)
            except Exception, ex:
                print "Error", resp, ex
            self.running = False
        else:
            console.log(resp)

    def print_header(self, time, run_id, caller, owner, org, targets, *args):
        # switch
        console.yellow('-' * 80, bold=1)
        console.yellow("ID: ", run_id, "", bold=True)
        console.yellow("#! switch [", targets, "]", bold=True)
        console.yellow('-' * 80, bold=1)

    def print_partial(self, run_id, time, caller, owner, org, targets, tags,
                      job_id, run_as, node=None, stdout=None, stderr=None):
        if self.last_line != job_id or self.last_node != node:
            console.blue('*' * 4, job_id, ':', node, run_as, '*' * 4, bold=1)
        self.last_line = job_id
        self.last_node = node
        if stdout:
            console.log(stdout)
        if stderr:
            console.red(stderr)

    def print_final(self, results):
        console.yellow("=" * 30, "Job stats:", "=" * 30, bold=True)
        for result in results:
            #console.blue("Run Id: ", result.get('run_id', ''), bold=1)
            console.blue("#! switch [", result['targets'], "] @",
                         result['jobid'], bold=1)
            if result.get('args', False):
                console.blue("Args: ",
                             ' '.join(result['args']), bold=1)
            for node in result['nodes']:
                if node['ret_code'] == 0:
                    color = console.green
                else:
                    color = console.red
                color('> ', node['node'], '[exit code: %s]' %
                      node['ret_code'], bold=1)


def _parser():
    _parser = argparse.ArgumentParser(description="CloudRunner shell")

    _common = argparse.ArgumentParser(add_help=False)

    rawtxtparser = argparse.RawTextHelpFormatter

    if CONFIG.mode == 'server':
        server = _common.add_argument(
            '-s', '--server', dest='server', required=False,
            default=os.environ.get('CLOUDRUNNER_SERVER', None),
            help='URL to the server to connect.'
            'Can be set also in \n'
            '/etc/cloudrunner/cloudrunner-shell.conf as:\n\n'
            '[General]\n'
            'dispatcher_uri=tcp://server:port\n\n'
            'or as env variable CLOUDRUNNER_SERVER')

        user_arg = _common.add_argument('-u', '--user',
                                        default=os.environ.get(
                                        'CLOUDRUNNER_USER', None),
                                        help='User name to authenticate at '
                                        'Master.\nCould be set as env variable '
                                        'CLOUDRUNNER_USER instead.')

        token_arg = _common.add_argument('-p', '--pass', dest='token',
                                         default=os.environ.get(
                                         'CLOUDRUNNER_TOKEN', None),
                                         help='Password/Token authenticate at '
                                         'Master.\nCould be set as env variable '
                                         'CLOUDRUNNER_TOKEN instead.')

        _common.add_argument('-v', '--verbose', action='store_true',
                             help="Show verbose info")
        _common.add_argument('-#', '--tag', action="append", dest="tags",
                             help='Label runs with tags. '
                             'Allows multiple values')

    tout_arg = _common.add_argument('-t', '--timeout', default=60,
                                    help='Timeout to expect result from '
                                    'Master in seconds.\nDefault is'
                                    ' %(default)s seconds.\n'
                                    'Set -1 for a persistent job')

    conf_arg = _common.add_argument('-c', '--config',
                                    default=None,
                                    help='Path to a config file.\n'
                                    'Defaults to %s seconds.' %
                                    CONFIG_SHELL_LOC)

    controllers = _parser.add_subparsers(dest='controller',
                                         help='Shell commands')

    # Run
    run = controllers.add_parser('run', parents=[_common],
                                 help='Run a cloudrunner script on nodes',
                                 formatter_class=rawtxtparser)

    run.add_argument('script', help='Script to run', nargs='?',
                     default=None)

    run.add_argument('-i', '--inline', action='store_true',
                     help='Pass inline script instead of a file')

    run.add_argument('-n', '--name', dest='name', help='Set an Id for the run')

    run.add_argument('--test', action='store_true',
                     dest='test', help='Perform a Test Run ('
                     'nothing is sent to nodes, just \'played\' on server')

    run.add_argument('-e', '--env', dest='env', required=False,
                           help='Initial Environment as JSON string')

    run.add_argument('--pipe-out', action='store_true',
                     default=True,
                     help='Show stdout from process pipe')

    run.add_argument('-L', '--include', action='append',
                     help='Pass scripts to be included into run\n'
                     'Could be applied multiple times,\n'
                     'or separated with semi-colon(:)')

    run.add_argument('-a', '--auth_remotely', action='store_true',
                     default=False,
                     help='Send authentication headers '
                     'when requesting script over http|https')

    run.add_argument('--single-user', action='store_true',
                     default=False,
                     help='Force single-user')

    if CONFIG.mode == 'server':
        attach_server_options(controllers, _common,
                              user_arg, token_arg, server)
    else:
        attach_standalone_options(controllers, _common)

    mode = controllers.add_parser('mode', help="Set CLI mode")

    mode.add_argument('mode', choices=['single-user', 'server'],
                      help="Set mode to single-user or server-controlled")

    mode.add_argument('-c', '--config', default=None,
                      help='Path to a config file.\n Defaults to %s seconds.' %
                      CONFIG_SHELL_LOC)
    return _parser


def attach_standalone_options(controllers, _common):
    configure = controllers.add_parser('configure', parents=[_common],
                                       help="Configure security credentials")

    configure.add_argument('-o', '--overwrite', action='store_true',
                           help="Overwrite existing configuration")

    details = controllers.add_parser('details', parents=[_common],
                                     help="Display current configuration")

    if CONFIG.security.peer_cache:
        peers = controllers.add_parser('peers',
                                       help="Perform action on remote peers")

        peer_tasks = peers.add_subparsers(dest='task',
                                          help="Perform tasks on peers")

        peer_tasks.add_parser('list', parents=[_common],
                              help="List registered peers")

        delete = peer_tasks.add_parser('delete', parents=[_common],
                                       help="Delete a registered peer")

        delete.add_argument('-n', '--name', required=True,
                            help="Peer name")

    if CONFIG.host_resolver:
        hosts = controllers.add_parser('hosts',
                                       help="Perform actions on host mappings")

        hosts = hosts.add_subparsers(dest='task',
                                          help="Perform tasks on hosts")

        hosts.add_parser('list', parents=[_common],
                         help="List all host mappings")

        add = hosts.add_parser('add', parents=[_common],
                               help="Add a new mapping")

        add.add_argument('-m', '--mapping', required=True, help="Mapping name")

        add.add_argument('-n', '--name', required=True,
                         help="Unique name for identification")

        add.add_argument('-i', '--host', required=True, help="host name")

        delete = hosts.add_parser('delete', parents=[_common],
                                  help="Delete a host mapping")

        delete.add_argument('-m', '--mapping', required=True,
                            help="Mapping name")

        delete.add_argument('-i', '--host', required=True, help="host name")


def attach_server_options(controllers, _common, user_arg, token_arg, server):
    attach = controllers.add_parser('attach', parents=[_common],
                                    help="Attach to an existing session")

    attach.add_argument('session_id', help="Session ID")

    attach.add_argument('targets', help='Targets to monitor', nargs='+',
                        default=None)

    notify = controllers.add_parser('notify', parents=[_common],
                                    help="Notify running job session")

    notify.add_argument('session_id', help="Session ID")

    notify.add_argument('job_id', help="Job ID")

    notify.add_argument('--targets', help='Targets to monitor', nargs='+',
                        default=None)

    notify.add_argument('input', help='Data to send', nargs='?',
                        default=None)

    notify.add_argument('-i', '--inline', action='store_true',
                        help='Pass inline data instead of a file')

    terminate = controllers.add_parser('terminate', parents=[_common],
                                       help="Terminate running job session")

    terminate.add_argument('session_id', help="Session ID")

    terminate.add_argument('--kill', action='store_true',
                           help="Send SIGKILL instead of SIGTERM")

    # Plugins
    controllers.add_parser('plugins', parents=[_common],
                           help='Shows available plugins on Master')

    # Plugins
    def dynamic_loader(prefix, parsedargs, **kwargs):
        if os.environ.get('COMP_LINE'):
            positionals = os.environ.get('COMP_LINE').split()[1:]
        else:
            positionals = sys.argv[1:]

        if positionals:
            if hasattr(Shell, positionals[0]):
                # known function
                return
            elif not filter(lambda x: not x.startswith('-'), positionals):
                # not a command, maybe help
                return

        global __AVAIL_PLUGINS__
        try:
            assert __AVAIL_PLUGINS__
        except NameError:
            ret = Shell(action="plugins",
                        user=user_arg.default,
                        server=server.default,
                        token=token_arg.default,
                        ).plugins_get(no_exit=True)
            if not ret:
                return []

            success, plugins = ret
            __AVAIL_PLUGINS__ = [str(p[0]) for p in plugins]
        opts = []
        if not positionals or positionals[0] not in __AVAIL_PLUGINS__:
            opts = [p for p in __AVAIL_PLUGINS__]
            for opt in opts:
                p_parser = controllers.add_parser(
                    opt, parents=[_common], help='Run a plugin on Master')

        else:
            plugin = positionals[0]
            p_parser = controllers.add_parser(
                plugin, parents=[_common], help='Plugin %s' % plugin)
            if positionals[1:]:
                p_parser.add_argument(
                    'xargs', nargs='+').completer = dynamic_completer
            positionals.append('--jhelp')
            PLUGINS[plugin] = 'plugin'
            success, opts = Shell(action="plugin",
                                  controller=plugin,
                                  user=user_arg.default,
                                  script="",
                                  inline=False,
                                  server=server.default,
                                  token=token_arg.default,
                                  timeout=2,
                                  xargs=positionals[1:]).plugin_get()[0]
            for opt in opts:
                if isinstance(opt, dict):
                    for k, v in opt.items():
                        _actions = p_parser.add_subparsers(dest=k)
                        for action in v:
                            _actions.add_parser(action)
                elif opt.startswith("@"):
                    # store_true
                    opt = opt.replace('@', '--')
                    p_parser.add_argument(
                        opt, action='store_true').completer = \
                        dynamic_completer
                else:
                    p_parser.add_argument(
                        opt).completer = dynamic_completer

    def dynamic_completer(prefix, parsed_args, **kwargs):
        global __AVAIL_PLUGINS__
        try:
            assert __AVAIL_PLUGINS__
        except NameError:
            success, plugins = Shell(action="plugins",
                                     user=user_arg.default,
                                     server=server.default,
                                     token=token_arg.default,
                                     ).plugins_get()
            __AVAIL_PLUGINS__ = [str(p[0]) for p in plugins]

        param = os.environ.get('COMP_LINE', prefix)
        positionals = param.split()[1:]

        if not positionals:
            return (p for p in __AVAIL_PLUGINS__)
        if positionals[0] not in __AVAIL_PLUGINS__:
            return (p for p in __AVAIL_PLUGINS__)

        positionals.append('--jhelp')

        try:
            success, opts = Shell(action="plugin",
                                  controller=positionals[0],
                                  user=user_arg.default,
                                  script="",
                                  inline=False,
                                  server=server.default,
                                  token=token_arg.default,
                                  timeout=2,
                                  xargs=positionals[1:]).plugin_get()[0]
        except Exception, ex:
            return (str(ex),)

        args = []
        try:
            for opt in opts:
                if isinstance(opt, dict):
                    args.extend(opts.values())
                elif opt.startswith('@'):
                    args.append(opt.replace('@', '--'))
                else:
                    args.append(opt)
        except Exception, ex:
            return (str(ex),)

        return (x for x in args)

    dynamic_loader(None, None)

    # Nodes
    list_nodes = controllers.add_parser('list_nodes', parents=[_common],
                                        help='List nodes on master')

    controllers.add_parser('list_active_nodes',
                           parents=[_common],
                           help='List nodes on master')

    controllers.add_parser('list_pending_nodes',
                           parents=[_common],
                           help='List pending nodes on master')


def main():
    ShellRunner().choose()

if __name__ == "__main__":
    main()
