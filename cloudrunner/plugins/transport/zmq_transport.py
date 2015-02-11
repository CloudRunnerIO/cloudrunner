import logging
import zmq

from cloudrunner.core.exceptions import ConnectionError, Unauthorized
from .base import Endpoint, Poller

LOGC = logging.getLogger('ZMQ Transport')


class SockWrapper(Endpoint):

    def __init__(self, endp, sock):
        self._sock = sock
        self.endpoint = endp

    def __repr__(self):
        return self.endpoint

    def __str__(self):
        return "SocketWrapper<%s>" % self.endpoint

    def fd(self):
        return self._sock.getsockopt(zmq.FD)

    def send(self, *frames):
        try:
            if len(frames) == 1:
                if isinstance(frames[0], list):
                    self._sock.send_multipart(frames[0])
                else:
                    self._sock.send(frames[0])
            else:
                self._sock.send_multipart(list(frames))
        except zmq.ZMQError, zerr:
            if self._sock.context.closed or \
                    zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                    or zerr.errno == zmq.ENOTSOCK:
                # System interrupt
                raise ConnectionError()
            LOGC.error(zerr)

    def recv(self, timeout=None):
        try:
            recv = None
            if timeout is not None:
                if self._sock.poll(timeout * 1000):
                    recv = self._sock.recv_multipart()
                else:
                    recv = None
            else:
                recv = self._sock.recv_multipart()
            if recv == ['NOT AUTHORIZED']:
                raise Unauthorized()
            return recv
        except zmq.ZMQError, zerr:
            if self._sock.context.closed or \
                    zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                    or zerr.errno == zmq.ENOTSOCK:
                # System interrupt
                raise ConnectionError()

    def recv_nb(self):
        # Non-blocking
        ev = self._sock.getsockopt(zmq.EVENTS)
        while (ev & zmq.POLLIN) > 0:

            data = None
            try:
                data = self._sock.recv_multipart(zmq.NOBLOCK)
                if data == ['NOT AUTHORIZED']:
                    raise Unauthorized()
                yield data
                ev = self._sock.getsockopt(zmq.EVENTS)
            except zmq.ZMQError:
                ev = self._sock.getsockopt(zmq.EVENTS)
                break

    def close(self):
        self._sock.close()


class PollerWrapper(Poller):

    def __init__(self, *sockets):
        self.poller = zmq.Poller()
        self._sockets = sockets
        for socket in self._sockets:
            self.poller.register(socket._sock, zmq.POLLIN)

    def poll(self, timeout=0):
        try:
            socks = dict(self.poller.poll(timeout))
        except zmq.ZMQError, zerr:
            if zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                    or zerr.errno == zmq.ENOTSOCK:
                raise ConnectionError()
            LOGC.exception(zerr)
            return []

        return [sock for sock in self._sockets if sock._sock in socks]
