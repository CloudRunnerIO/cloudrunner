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

import cmd
import glob
import logging
import os
import re
import shlex
import sys

from cloudrunner import CONFIG_SHELL_LOC
from cloudrunner import LIB_DIR
from cloudrunner.shell.api import CloudRunner
from cloudrunner.core import message
from cloudrunner.util.config import Config
from cloudrunner.util.logconfig import configure_loggers
from cloudrunner.util.shell import colors
from cloudrunner.util.shell import Console
from cloudrunner.util.http import load_from_link
from cloudrunner.util.http import parse_url

try:
    import readline
except ImportError:
    pass

CONFIG = Config(CONFIG_SHELL_LOC)
PLUGINS = {}
LIBRARY_ITEM = re.compile(r'\[(?P<store>\w*)\]\://')
HTTP_ITEM = re.compile(r'https*\://.*')

LOG_FORMAT = '>>%(levelname)s:%(message)s'

configure_loggers(CONFIG.verbose_level or logging.INFO,
                  CONFIG.log_file or LIB_DIR + 'cloudrunner-node.log',
                  log_format=LOG_FORMAT)

LOG = logging.getLogger('ShellRunner')

console = Console()


class Exit(Exception):
    pass


LANGS = {
    'bash': '#! /bin/bash',
    'sh': '#! /bin/sh',
    'python': '#! /usr/bin/python',
    'perl': '#! /usr/bin/perl',
    'ruby': '#! /usr/bin/ruby',
    'puppet': '#! /usr/bin/puppet',
    'nodejs': '#! /usr/bin/nodejs'
}


class Shell(cmd.Cmd):

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

        self.kwargs.update(
            {'auth_user': os.environ.get('CLOUDRUNNER_USER'),
             'auth_token': os.environ.get('CLOUDRUNNER_TOKEN'),
             'dispatcher_uri': os.environ.get('CLOUDRUNNER_SERVER')})

        if 'no_colors' in kwargs:
            colors.disable()

        if 'NO_COLORS' in os.environ:
            colors.disable()

        cmd.Cmd.__init__(self)

        self.target = "local"
        self.included_files = []
        self.attached_files = []
        self.buffer = []
        self.last_buffer = []
        self.last_options = ""
        self.running = False
        self.lang = 'bash'
        self.save_history = False
        self.runtime_history = []
        self._api = None

        assert self.api

    def preloop(self):
        try:
            histfile = os.environ.get("CLOUDRUNNER_HISTFILE")
            if histfile:
                readline.read_history_file(histfile)
                self.save_history = True
                histsize = os.environ.get("CLOUDRUNNER_HISTSIZE", 10000)
                readline.set_history_length(histsize)
        except Exception, ex:
            print ex
            pass

    def _save_history(self):
        if self.save_history:
            histfile = os.environ.get("CLOUDRUNNER_HISTFILE")
            if histfile:
                readline.write_history_file(histfile)

    @property
    def nodes(self):
        if self.api.transport.mode == "server":
            if not hasattr(self, "_nodes"):
                self._nodes = self.api.list_active_nodes()
            return self._nodes
        else:
            return [x[0] for x in self.api.transport.peer_store]

    @property
    def api(self):
        if self._api is None:
            self._api = CloudRunner.from_config(CONFIG, **self.kwargs)
        return self._api

    def handle_int(self, *args, **kwargs):
        print

    @property
    def prompt(self):
        opts = []
        if self.included_files:
            opts.append("I:%s" % len(self.included_files))
        if self.attached_files:
            opts.append("A:%s" % len(self.attached_files))
        if self.buffer and [x for x in self.buffer if x.strip()]:
            opts.append("L:%s" % len([x for x in self.buffer if x.strip()]))

        if opts:
            return "(%s)[%s][%s]:" % (self.lang, "][".join(opts), self.target)
        else:
            return "(%s)[%s]:" % (self.lang, self.target)

    def default(self, line):
        if line == "EOF":
            return self.do_quit(line)
        self.buffer.append(line)
        self.runtime_history.append(line)
        if self.target == "local":
            return self.do_run("")

    def emptyline(self):
        self.buffer.append("")
        if self.buffer[-2:] == ["", ""]:
            return self.do_run("")
        return False

    def help_lang(self, line):
        console.yellow("Choose script language")
        console.white("=" * 20)
        console.yellow("Syntax")
        print colors.yellow("\tlang", bold=1), \
            colors.yellow("python")
        console.yellow("Choose from bash, sh, python, perl, "
                       "ruby, nodejs, puppet")

    def do_history(self, arg):
        console.yellow("Execution history:", bold=1)
        console.white("\n".join(self.runtime_history))

    def do_lang(self, line):
        if not line:
            line = "bash"
        if line not in LANGS:
            # Check for short
            items = [l for l in LANGS.keys() if l.startswith(line)]
            if len(items) != 1:
                console.red("Language not recognized")
                self.help_lang("")
                return
            else:
                line = items[0]
        self.lang = line

    def help_switch(self):
        console.yellow("Select remote targets")
        console.white("=" * 20)
        console.yellow("Syntax")
        print colors.yellow("\tswitch", bold=1), \
            colors.yellow("host1 host2 os=linux dist=centos")
        console.yellow("Use empty switch for local run")

    def do_switch(self, target):
        """Switch CloudRunner target"""
        self.runtime_history.append("#! switch %s" % target)
        if not target:
            self.target = "local"
        else:
            self.target = target

    def complete_switch(self, opt, full, arg_start, arg_end):
        """Switch CloudRunner target"""
        return [node for node in self.nodes if not opt or node.startswith(opt)]

    def do_quit(self, arg):
        print
        try:
            if self.save_history:
                self._save_history()
        except Exception:
            pass
        self.api.transport.terminate(force=True)
        return True

    def do_include_file(self, arg):
        """Files to include when executing command"""
        if not arg:
            return
        if not os.path.exists(arg):
            if HTTP_ITEM.match(arg):
                self.included_files.append((arg, arg))
            elif arg in self.api.library['inlines'].keys():
                self.included_files.append((self.api.library['inlines'][arg],
                                            arg))
            else:
                console.red("File '%s' doesn't exist" % arg)
        else:
            self.included_files.append((arg, self._sanitize_path(arg)))

    def do_attach_file(self, arg):
        """Files to attach when executing command"""
        if not arg:
            return
        if not os.path.exists(arg):
            if HTTP_ITEM.match(arg):
                self.attached_files.append((arg, arg))
            elif arg in self.api.library.keys():
                self.attached_files.append((self.api.library[arg], arg))
            else:
                console.red("File '%s' doesn't exist" % arg)
        else:
            self.attached_files.append((arg, self._sanitize_path(arg)))

    def _sanitize_path(self, path):
        cur_dir = os.path.abspath(os.path.curdir)
        common = os.path.commonprefix([cur_dir, os.path.abspath(path)])
        if common == cur_dir:
            # Safe
            return path
        else:
            console.yellow("The specified path is outside current dir. "
                           "It will be available on the server "
                           "relative to the working dir as:")
            console.green(os.path.relpath(path, common), bold=1)
            return os.path.relpath(path, common)

    def _browse_local(self, pattern):
        res = []
        pwd = os.path.join(os.path.abspath(os.path.curdir))
        search_dir = os.path.dirname(os.path.join(pwd, pattern))
        selector = pattern.rpartition('/')[2]
        glob_pattern = os.path.join(search_dir, selector) + '*'
        res = [os.path.relpath(p, search_dir)
               for p in list(glob.glob(glob_pattern))]
        return res

    def _browse_remote(self, pattern, target=None):
        res = []
        if self.api.library[target]:
            res.extend([k for k, v in self.api.library[target].items()
                        if v.startswith(pattern)])
        return res

    def complete_attach_file(self, opt, full, arg_start, arg_end):
        cptext = full[len("attach_file") + 1:]
        return self._browse(cptext)

    def complete_include_file(self, opt, full, arg_start, arg_end):
        cptext = full[len("include_file") + 1:]
        return self._browse_local(cptext) + self._browse_remote(cptext,
                                                                'inlines')

    def do_detach_file(self, arg):
        """Files to detach when executing command"""
        for (full, name) in self.attached_files:
            if name == arg:
                self.attached_files.remove((full, name))

    def do_exclude_file(self, arg):
        for (full, name) in self.included_files:
            if name == arg:
                self.included_files.remove((full, name))

    def complete_exclude_file(self, opt, full, arg_start, arg_end):
        cptext = full[arg_start:]
        res = []
        for (full, name) in self.included_files:
            if name.startswith(cptext):
                res.append(name)
        return res

    def complete_detach_file(self, opt, full, arg_start, arg_end):
        cptext = full[arg_start:]
        res = []
        for (full, name) in self.attached_files:
            if name.startswith(cptext):
                res.append(name)
        return res

    def do_show_workflow(self, arg):
        if arg not in self.api.workflows:
            console.red("Workflow not found")

        else:
            store = LIBRARY_ITEM.match(arg).group(1)
            wf_name = LIBRARY_ITEM.sub('', arg)
            ares = self.api.show_workflow(store, wf_name)
            console.yellow(ares)

    def complete_show_workflow(self, opt, full, arg_start, arg_end):
        cptext = full[len("show_workflow") + 1:]
        return self._browse_remote(cptext, target="workflows")

    def do_load(self, arg):
        store = LIBRARY_ITEM.match(arg).group(1)
        wf_name = LIBRARY_ITEM.sub('', arg)
        ares = self.api.show_workflow(store, wf_name)
        self.buffer = ares.splitlines()

    def complete_load(self, opt, full, arg_start, arg_end):
        cptext = full[len("load") + 1:]
        return self._browse_remote(cptext, target="workflows")

    def do_show_inline(self, arg):
        if arg not in self.api.library['inlines']:
            console.red("Inline not found")
        else:
            inl_name = LIBRARY_ITEM.sub('', arg)
            ares = self.api.show_inline(inl_name)
            console.yellow(ares)

    def complete_show_inline(self, opt, full, arg_start, arg_end):
        cptext = full[len("show_inline") + 1:]
        return self._browse_remote(cptext, target="inlines")

    def help_clear(self):
        console.yellow("Clears current buffer")

    def do_clear(self, line):
        self.buffer = []

    def help_clear_last(self):
        console.yellow("Clears last line from buffer")

    def do_clear_last(self, line):
        self.buffer.pop()
        self.do_shell("")

    def do_shell(self, line):
        console.yellow("-- Current script --")
        console.white("\n".join(self.buffer))
        console.yellow("-- End --")

    def do_list_included_files(self, arg):
        for fl in self.included_files:
            console.white(fl[1])

    def do_list_attached_files(self, arg):
        for fl in self.attached_files:
            console.white(fl[1])

    def help_rerun(self):
        console.yellow("Re-run last executed command")

    def do_rerun(self, line):
        self.buffer = self.last_buffer
        self.do_run(self.last_options)

    def help_continue(self):
        console.yellow("Continue last executed script")

    def do_continue(self, line):
        self.buffer = self.last_buffer
        self.do_shell("")

    def help_run(self):
        console.yellow("Run command")
        console.white("=" * 20)
        console.yellow("Options")
        console.white("-" * 20)
        console.yellow("--resume=[uuid]")
        console.yellow("\tResume a specific job with its ID")

    def do_run(self, line):
        self.running = True

        script = "\n".join(self.buffer)
        self.last_buffer = self.buffer
        self.last_options = line
        self.buffer = []

        if not script.strip():
            # Nothing to run
            return

        self._save_history()

        options = []
        if line.strip():
            _opts = [opt.strip() for opt in line.split()]
            for _opt in _opts:
                k, _, v = _opt.partition("=")
                if k and v:
                    options.append(_opt)
        elif hasattr(self, "last_session_id"):
            options.append('--resume=%s' % self.last_session_id)

        if self.target == "local":
            self.current_session = 'local'
            ares = self.api.run_local(script)
        else:
            self.current_session = None
            includes, args = self._includes()
            if args:
                options.extend(args)
            ares = self.api.run_remote("#!switch[%s] %s\n%s\n\n%s" % (
                self.target,
                " ".join(options),
                LANGS[self.lang],
                script),
                includes=includes,)

        self.render_msg(ares)

        self.running = False

    def render_msg(self, ares):
        cur_job_id = None
        last_node = None

        for msg in ares.iter():
            if isinstance(msg, message.PipeMessage):
                if msg.node == 'Job Started':
                    self.current_session = msg.job_id
                    # ToDo: change this
                    continue
                if not self.current_session:
                    self.current_session = msg.job_id

                job_id = getattr(msg, "session_id", None)

                if job_id != self.current_session:
                    continue

                if job_id != cur_job_id:
                    console.green("========== JOB: @%s %s ==========" % (
                        msg.run_as, job_id))
                    cur_job_id = job_id

                if msg.node != last_node:
                    console.blue("%s@%s$" % (msg.run_as, msg.node))
                if msg.stdout.strip():
                    console.white(msg.stdout)
                if msg.stderr:
                    console.red(msg.stderr)

                last_node = msg.node

            if isinstance(msg, message.FinishedMessage):
                job_id = getattr(msg, "session_id", None)
                if job_id != self.current_session:
                    continue
                console.green("========== Summary [%s] ==========" %
                              msg.session_id)
                try:
                    self.last_session_id = None
                    for node in msg.result:
                        line = "%s: exit code: %s" % (node['node'],
                                                      node['ret_code'])
                        if node['ret_code']:
                            console.red(line)
                        else:
                            console.yellow(line)
                except:
                    continue

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
                                "Server returned code:", status, _script)
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

    def mode(self):
        if self.args.mode:
            CONFIG.update('General', 'mode', self.args.mode)
            CONFIG.reload()

    def do_list_nodes(self, *args):
        result = self.api.list_nodes()
        console.green("=" * 80)
        console.green("Available nodes on Master", bold=1)
        console.green("=" * 80)

        for node in result:
            console.blue(node)

    def do_list_active_nodes(self, *args, **kwargs):
        result = self.api.list_active_nodes()
        console.green("=" * 80)
        console.green("Available nodes on Master", bold=1)
        console.green("=" * 80)

        for node in result:
            console.blue(node)

    def do_list_pending_nodes(self, *args, **kwargs):
        result = self.api.list_pending_nodes()

        console.green("=" * 80)
        console.green("Pending nodes on Master", bold=1)
        console.green("=" * 80)

        for node in result:
            console.blue(node)

    def do_list_plugins(self, *args, **kwargs):
        result = self.api.list_plugins()

        console.green("=" * 80)
        console.green("Plugins available on Master", bold=1)
        console.green("=" * 80)

        console.new_line()

        console.green('*' * 3, "Plugins", '*' * 3)
        for arg in result[0]:
            console.blue(arg[0])
            console.yellow('\t' + '\n\t'.join(arg[1]))

        console.new_line()
        console.green('*' * 3, "CLI Plugins", '*' * 3)
        for arg in result[1]:
            console.blue(arg[0])
            console.yellow('\t%s' % arg[1])

    def do_plugin(self, *args):
        params = args[0].split(" ")
        plugin_name = params.pop(0)
        params = shlex.split(" ".join(params))
        result = self.api.get_plugin(plugin_name, args=params)

        if result:
            for res in result:
                success, msg = res
                if success:
                    console.blue(msg)
                else:
                    console.red(msg)
        else:
            console.red('Error: %s' % result)

    def complete_plugin(self, opt, full, arg_start, arg_end):
        _plugins = []
        if not opt and arg_start > len("plugin"):
            # Just one plugin
            return _plugins
        if not hasattr(self, "_plugins"):
            _plugins = []
            if self.api.transport.mode == "server":
                try:
                    result = self.api.list_plugins()
                    _plugins = [p[0] for p in result[1]]
                except Exception, ex:
                    print ex
            self._plugins = _plugins

        return [p for p in self._plugins if not opt or p.startswith(opt)]

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

    def _includes(self):
        libs = []
        options = []

        for (_file, name) in self.included_files:
            if LIBRARY_ITEM.match(name) or HTTP_ITEM.match(_file):
                # From library
                options.append('--include-lib="%s"' % _file)
            else:
                try:
                    data = {}
                    with open(_file) as f:
                        incl_content = f.read()
                        data["name"] = name
                        data["inline"] = True
                        data["source"] = incl_content
                        libs.append(data)
                except IOError:
                    console.red("Cannot open include file %s" % _file)

        for (_file, name) in self.attached_files:
            if LIBRARY_ITEM.match(name) or HTTP_ITEM.match(_file):
                # From library
                options.append('--attach-lib="%s"' % _file)
            else:
                try:
                    data = {}
                    with open(_file) as f:
                        incl_content = f.read()
                        data["name"] = name
                        data["source"] = incl_content
                        libs.append(data)
                except IOError:
                    console.red("Cannot open attach file %s" % _file)
        return libs, options

    def terminate(self):
        self.api.close()


def main():
    sh = Shell()
    run = True
    while run:
        try:
            run = sh.cmdloop()
        except KeyboardInterrupt:
            print
        except Exception, ex:
            console.red("Error: %r" % ex)

    sh.terminate()


if __name__ == "__main__":
    main()
