import json
import logging
import requests

from cloudrunner.plugins.transport.base import (TransportBackend,
                                                Endpoint,
                                                Poller)
from cloudrunner.core.message import StatusCodes


LOG = logging.getLogger()


class Dispatch(object):

    def __init__(self, initial, **kwargs):
        self.method = "post"
        self.path = "dispatch:execute"
        self.initial = dict(data=initial)
        self.initial.update(kwargs)

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        send_func = (yield None)

        r = send_func(self.method, self.path,
                      data=json.dumps(self.initial))
        try:
            _uuid = r.json()['dispatch']['uuid']
            assert _uuid

            r = send_func('get', "logs:output", args=[_uuid])
            print r.json()
            log_info = r.json()['output']
            yield (StatusCodes.PIPEOUT,
                   log_info['created_at'],
                   "PARTIAL",
                   log_info['uuid'],
                   )

        except Exception, ex:
            LOG.exception(ex)
            raise StopIteration("Cannot start remote execution on server")
        finally:
            raise StopIteration()

    next = __next__

COMMAND_MAP = {
    "dispatch": Dispatch,
}


class OpQueue(object):

    def __init__(self, session, base_api_url):
        self.token = None
        self.base_api_url = base_api_url
        self.base_api_url = self.base_api_url.rstrip('/')
        self.queue = []
        self.session = session

    def url(self, target, *args, **kwargs):
        return "/".join([self.base_api_url] +
                        list(target.split(':')) +
                        list(args))

    def send(self, user, auth_type, pass_token, command, payload=None,
             **kwargs):

        if not self.token:
            try:
                # request token
                r = self.session.get(self.url("auth:login", user, pass_token))
                self.token = r.json()['login']['token']
                self.session.headers.update({'Cr-User': user,
                                             'Cr-Token': self.token})
            except Exception, ex:
                LOG.exception(ex)
                raise Exception("Cannot retrieve auth token. "
                                "Check configuration")

        cmd_class = COMMAND_MAP.get(command)
        if not cmd_class:
            raise Exception("Invalid command: %s" % command)

        cmd = cmd_class(payload, **kwargs)

        self.iter = iter(cmd)
        self.iter.next()
        val = self.iter.send(lambda meth, path, args=[], data=None:
                             self.session.request(meth, self.url(path, *args),
                                                  data=data))

    def recv(self, timeout=2):
        ret_value = self.iter.next()
        return ret_value


class RESTTransport(TransportBackend):

    config_options = ["node_id", "api_url",
                      "security.peer_cache", "mode"]

    def __init__(self, **kwargs):
        api_url = kwargs.get('api_url') or 'http://127.0.0.1:5558/rest/'
        self.session = requests.Session()
        self.op_queue = OpQueue(self.session, api_url)

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
