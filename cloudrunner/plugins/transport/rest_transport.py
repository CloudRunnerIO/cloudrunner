import msgpack
import logging
import os
import requests
import time

from cloudrunner import LIB_DIR
from cloudrunner.core.message import StatusCodes
from cloudrunner.plugins.transport.base import (TransportBackend)
from cloudrunner.util.cert_store import CertStore
from cloudrunner.util.net import HostResolver

LOG = logging.getLogger()
R_LOG = logging.getLogger("requests")
R_LOG.setLevel(logging.ERROR)


class OutputterMixin(object):

    def pipe(self, seq, ts, uuid, step, run_as, node, stdout, stderr):
        return (StatusCodes.PIPEOUT, ts, StatusCodes.PIPEOUT,
                uuid, ts, seq, step, '', '', uuid,
                run_as, node, stdout, stderr)

    def finished(self, seq, ts, uuid, step, result):
        return (StatusCodes.FINISHED, ts, StatusCodes.FINISHED,
                uuid, ts, seq, '', '', step, result)


class Dispatch(OutputterMixin):

    def __init__(self, initial, **kwargs):
        self.method = "post"
        self.path = "dispatch:execute"
        self.initial = dict(data=initial)
        self.initial.update(kwargs)

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)
        yield "Starting"
        inc = 1
        r = send_func(self.method, self.path,
                      data=msgpack.packb(self.initial),).json()
        try:
            _uuid = r.get('dispatch', {}).get('uuid')

            if not _uuid:
                yield "Error"
                return

            running = True
            etag = None
            while running:
                r = send_func('get', "logs:output", args=[_uuid],
                              headers={'Etag': etag})
                if not r.status_code == 200:
                    yield self.pipe(0, '', 1, '', '', '',
                                    "Invalid response from server: %s" %
                                    r.status_code)
                r = r.json()
                outputs = r['outputs']
                for log_info in outputs:
                    status = log_info.get('status')
                    etag = int(log_info.get('etag', 0)) + 1
                    for step in log_info.get('steps', []):
                        lines = step.get('lines')
                        step_id = step.get('step')
                        if lines:
                            for line in lines:
                                ts = line.pop(0)
                                out_type = line.pop(0)
                                stdout, stderr = "", ""
                                if out_type == 'O':
                                    # stdout
                                    stdout = "\n".join(line)
                                elif out_type == 'E':
                                    # stderr
                                    stderr = "\n".join(line)
                                yield self.pipe(inc, ts, _uuid,
                                                step_id,
                                                step.get('run_as'),
                                                step['node'],
                                                stdout,
                                                stderr
                                                )
                                inc += 1
                        if status == "finished":
                            log_info = step['result']

                            yield self.finished(inc, ts, _uuid,
                                                step_id, log_info)
                            running = False
                time.sleep(1)

        except Exception, ex:
            LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__


class ListNodes(object):

    def __init__(self, initial, **kwargs):
        self.method = "get"
        self.initial = {}

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)
        yield "Starting"
        r = send_func(self.method, self.path)
        try:
            yield [n[0] for n in r.json()['nodes']]
        except Exception:
            # LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__


class ListActive(ListNodes):
    path = "dispatch:active_nodes"


class ListNodes(ListNodes):
    path = "dispatch:nodes"


class ListPending(ListNodes):
    path = "dispatch:pending_nodes"


class LibWorkflows(object):
    method = "get"
    path = "repository:workflows"

    def __init__(self, initial, **kwargs):
        self.initial = {}

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)
        yield "Starting"
        r = send_func(self.method, self.path)
        try:
            yield r.json()["workflows"]
        except Exception:
            # LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__


class LibInlines(object):
    method = "get"
    path = "repository:inlines"

    def __init__(self, initial, **kwargs):
        self.initial = {}

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)
        yield "Starting"
        r = send_func(self.method, self.path)
        try:
            yield r.json()["inlines"]
        except Exception:
            # LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__


class GetWorkflow(object):
    method = "get"
    path = "repository:workflows"

    def __init__(self, initial, wf_id=None, store=None, **kwargs):
        self.initial = {}
        self.wf_id = wf_id.lstrip('/')
        self.store = store

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)
        yield "Starting"
        r = send_func(self.method, self.path,
                      args=[self.wf_id],
                      q=dict(store=self.store))
        try:
            yield r.json()["workflow"]['content']
        except Exception:
            # LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__


class GetInline(object):
    method = "get"
    path = "repository:inlines"

    def __init__(self, initial, inl_id=None, store=None, **kwargs):
        self.initial = {}
        self.inl_id = inl_id.lstrip('/')

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)
        yield "Starting"
        r = send_func(self.method, self.path, args=[self.inl_id])
        try:
            yield r.json()["inline"]['content']
        except Exception:
            # LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__


COMMAND_MAP = {
    "dispatch": Dispatch,
    "list_active_nodes": ListActive,
    "list_nodes": ListNodes,
    "list_pending_nodes": ListPending,
    "workflows": LibWorkflows,
    "inlines": LibInlines,
    "workflow": GetWorkflow,
    "inline": GetInline,
}


class OpQueue(object):

    def __init__(self, session, base_api_url):
        self.token = None
        self.base_api_url = base_api_url
        self.base_api_url = self.base_api_url.rstrip('/')
        self.queue = []
        self.session = session

    def url(self, target, *args, **kwargs):
        path = "/".join([self.base_api_url] +
                        list(target.split(':') + list(args)))
        q_search = ""
        if kwargs:
            q_search = "&".join(["=".join([k, v])
                                 for k, v in kwargs.items()])

        return "%s?%s" % (path, q_search)

    def partial_send(self, method, url,
                     args=None, data=None, q=None, headers=None):
        _headers = dict(headers or {})
        _headers["Content-Type"] = "application/json"
        r = self.session.request(method,
                                 self.url(url, *(args or []), **(q or {})),
                                 data=data, headers=_headers)
        if r.status_code == 401:
            self.refresh_token()
            # Access denied
            r = self.session.request(method, self.url(url, *(args or []),
                                                      **(q or {})),
                                     data=data, headers=_headers)
        return r

    def refresh_token(self):
        try:
            # request token
            r = self.session.get(self.url("auth:login",
                                          self.user, self.pass_token))
            self.token = r.json()['login']['token']
            self.session.headers.update({'Cr-User': self.user,
                                         'Cr-Token': self.token})
        except Exception, ex:
            LOG.exception(ex)
            raise Exception("Cannot retrieve auth token. "
                            "Check configuration")

    def send(self, user, auth_type, pass_token, command, payload=None,
             **kwargs):

        self.user = user
        self.pass_token = pass_token
        if not self.token:
            self.refresh_token()

        cmd_class = COMMAND_MAP.get(command)
        if not cmd_class:
            LOG.warn("Command %s not found" % command)
            raise Exception("Invalid command: %s" % command)

        cmd = cmd_class(payload, **kwargs)

        self.iter = iter(cmd)
        self.iter.next()
        self.iter.send(self.partial_send)

    def recv(self, timeout=2):
        try:
            ret_value = self.iter.next()
            return ret_value
        except StopIteration:
            return None


class RESTTransport(TransportBackend):

    config_options = ["node_id", "api_url",
                      "security.peer_cache", "host_resolver"]

    def __init__(self, **kwargs):
        api_url = kwargs.get('api_url') or 'http://127.0.0.1/rest/'
        self.session = requests.Session()
        self.op_queue = OpQueue(self.session, api_url)
        host_resolver_uri = kwargs.get("host_resolver")
        if host_resolver_uri:
            self.host_resolver = HostResolver(host_resolver_uri)
        else:
            self.host_resolver = None

        self.peer_cache = kwargs.get("peer_cache")
        if not self.peer_cache:
            self.peer_cache = os.path.join(LIB_DIR,
                                           'cloudrunner-cli',
                                           'peer_cache.db')
        self.peer_store = CertStore(self.peer_cache)

    def configure(self, overwrite=False, **kwargs):
        pass

    def consume_queue(self, type, ident=None, *args, **kwargs):
        pass

    def publish_queue(self, type, ident=None, *args, **kwargs):
        return self.op_queue

    def create_poller(self, *sockets):
        pass

    def prepare(self):
        pass

    def terminate(self, force=False):
        self.session.close()

    def loop(self):
        pass
