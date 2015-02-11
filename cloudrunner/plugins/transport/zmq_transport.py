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

import msgpack
import logging
import M2Crypto as m
import os
import random
from string import ascii_letters
from socket import gethostname
from threading import Event
from threading import Thread
import time
import zmq
from zmq.eventloop import ioloop

from cloudrunner import CONFIG_SHELL_LOC, LIB_DIR
from cloudrunner.core.exceptions import ConnectionError
from cloudrunner.plugins.transport.base import (TransportBackend,
                                                Endpoint,
                                                Poller)
from cloudrunner.core.exceptions import Unauthorized
from cloudrunner.util.cert_store import CertStore
from cloudrunner.util.config import Config
from cloudrunner.util.net import HostResolver
from cloudrunner.util.tlszmq import TLSZmqClientSocket
from cloudrunner.util.string import stringify

LOGC = logging.getLogger("ZMQ Cli Backend")


class ZmqCliTransport(TransportBackend):
    MODE_SERVER = "server"
    MODE_LOCAL = "single-user"
    LOCAL_DISP = 'tcp://127.0.0.1:35559'
    proto = 'zmq+ssl'
    config_options = ["node_id", "master_pub", "master_repl",
                      "worker_count", "sock_dir", "security.server",
                      "security.ssl_cert", "security.ssl_key",
                      "host_resolver", "security.cert_pass",
                      "security.peer_cache", "mode"]

    def __init__(self, mode=None, dispatcher_uri=None, **kwargs):
        self.mode = mode or self.MODE_LOCAL
        self.dispatcher_uri = dispatcher_uri or self.LOCAL_DISP
        self.context = zmq.Context()
        self.stopped = Event()
        self.ssl_thread_event = Event()
        self.ssl_init_event = Event()
        self._sockets = []
        self.proxy_uri = "inproc://ssl-proxy-sock"
        self.endpoints = {
            'requests': (self.proxy_uri, self.proxy_uri)
        }
        self.local_dispatcher = None

        self.ssl_cert = kwargs.get("ssl_cert")
        self.ssl_key = kwargs.get("ssl_key")
        self.cert_pass = kwargs.get("cert_pass")
        self.peer_cache = kwargs.get("peer_cache")

        if self.ssl_cert and \
                os.path.exists(self.ssl_cert):
            try:
                ssl_cert = m.X509.load_cert(self.ssl_cert)
                self.properties.append(('Certificate fingerprint',
                                        ssl_cert.get_fingerprint('sha1')))
                self.properties.append(('CLI cert CN',
                                        ssl_cert.get_subject().CN))
            except:
                pass

        if self.mode == self.MODE_LOCAL:
            if not self.peer_cache:
                self.peer_cache = os.path.join(LIB_DIR,
                                               'cloudrunner-cli',
                                               'peer_cache.db')
            self.peer_store = CertStore(self.peer_cache)

            host_resolver_uri = kwargs.get("host_resolver")
            if host_resolver_uri:
                self.host_resolver = HostResolver(host_resolver_uri)
            else:
                self.host_resolver = None

    def loop(self):
        ioloop.IOLoop.instance().start()

    def prepare(self):
        LOGC.debug("Starting ZMQ Transport")

        if (self.mode == self.MODE_LOCAL and
                not (self.ssl_cert and self.ssl_key)):
            print("Client is not configured. Run with\n"
                  "\tcloudrunner-exec configure\n"
                  "to perform initial configuration, or manually edit the "
                  "config file to set security credentials")
            exit(2)

        if self.mode == self.MODE_LOCAL:
            self.sessions = {}
            self.local_dispatcher = Thread(target=self.run_local_dispatcher)
            self.local_dispatcher.start()
        else:
            if not self.dispatcher_uri:
                print "ERROR: Server URL not found"
                exit(1)
            self.run_remote_proxy()

    def _ssl_socket_device(self, context):
        LOGC.debug("Starting new SSL thread")

        ssl_socket = TLSZmqClientSocket(self.context,
                                        self.dispatcher_uri,
                                        self.endpoints['requests'][0],
                                        self.ssl_thread_event,
                                        init_event=self.ssl_init_event,
                                        route_packets=False)
        ssl_socket.start()
        ssl_socket.shutdown()
        LOGC.debug("Exiting SSL thread")

    def ssl_start(self):
        self.ssl_thread = Thread(target=self._ssl_socket_device,
                                 args=[self.context])
        self.ssl_thread.start()

    def ssl_stop(self):
        self.ssl_thread_event.set()
        self.ssl_thread.join(1)
        self.ssl_thread_event.clear()

    def run_remote_proxy(self):
        self.ssl_start()

    def run_local_dispatcher(self):
        LOGC.debug("Starting local dispatcher")

        self.router_uri = 'inproc://router-proxy-sock'

        from cloudrunner.shell.local_session import Session

        dispatcher = self.context.socket(zmq.DEALER)
        dispatcher.bind(self.proxy_uri)

        session_worker_uri = 'inproc://session_worker-sock'

        worker = self.context.socket(zmq.DEALER)
        worker.bind(session_worker_uri)

        poller = zmq.Poller()
        poller.register(dispatcher, zmq.POLLIN)
        poller.register(worker, zmq.POLLIN)

        def router():
            LOGC.debug("Starting router")

            ssl_proxy_uri = 'ipc:///tmp/router-ssl-proxy-%s-sock'

            router_sock = self.context.socket(zmq.DEALER)
            router_sock.bind(self.router_uri)

            remote_socks = {}

            poller = zmq.Poller()
            poller.register(router_sock, zmq.POLLIN)

            def validate_peer(x509):
                cn = x509.get_subject().CN
                fprint = x509.get_fingerprint('sha1')

                if (cn, fprint) not in self.peer_store:
                    LOGC.warn(
                        "Adding new peer certificate into cache(%s:%s)" % (
                            cn, fprint))
                    if not self.peer_store.insert(cn, fprint):
                        return False
                else:
                    store_fp = self.peer_store.get_fingerprint(cn)
                    if not store_fp:
                        LOGC.error("A fingerprint (%s) already exists, but "
                                   "is attached to different common name: %s. "
                                   "Remove manually the stored data "
                                   "to approve the change" %
                                   (fprint,
                                    self.peer_store.get_common_name(fprint)))
                        return False
                    elif store_fp != fprint:
                        LOGC.error("Peer certificate for server(%s) has "
                                   "different fingerprint into the "
                                   "Certificate store\n"
                                   "Expected: %s\n"
                                   "Current: %s\n"
                                   "Remove manually the stored data "
                                   "to approve the change" %
                                   (cn, fprint, store_fp))
                        return False
                return True

            while not self.stopped.is_set():
                try:
                    ready = dict(poller.poll(500))
                    if router_sock in ready:
                        frames = router_sock.recv_multipart()
                        target = frames.pop(0)
                        ip = frames.pop(0)
                        if ":" not in ip:
                            # Use default port
                            ip = "%s:5552" % ip
                        ip = "tcp://%s" % ip
                        if ip not in remote_socks:
                            proxy_sock = self.context.socket(zmq.DEALER)
                            proxy_sock.setsockopt(zmq.IDENTITY, frames[1])
                            uri = ssl_proxy_uri % target
                            proxy_sock.bind(uri)
                            ssl_socket = TLSZmqClientSocket(
                                self.context, ip, uri, self.ssl_thread_event,
                                route_packets=False,
                                bind_socket=False,
                                cert=self.ssl_cert,
                                key=self.ssl_key,
                                cert_password=self.cert_pass,
                                skip_warnings=True,
                                validate_peer=validate_peer)
                            Thread(target=ssl_socket.start).start()
                            remote_socks[ip] = [proxy_sock, ssl_socket]
                            poller.register(proxy_sock, zmq.POLLIN)
                            # ping socket to establish connection
                            proxy_sock.send_multipart(['PING'])
                        proxy_sock = remote_socks[ip][0]
                        proxy_sock.send_multipart(frames)
                    for sock in ready:
                        if sock != router_sock:
                            frames = sock.recv_multipart()
                            router_sock.send_multipart(frames)

                except zmq.ZMQError, zerr:
                    if self.context.closed or \
                            zerr.errno == zmq.ETERM or \
                            zerr.errno == zmq.ENOTSUP or \
                            zerr.errno == zmq.ENOTSOCK:
                        # System interrupt
                        break
                except Exception, ex:
                    LOGC.error(ex)
            for sock in remote_socks.values():
                sock[0].close(0)
                sock[1].shutdown()
            LOGC.debug("Exiting router")

        self.router_thread = Thread(target=router, args=[])
        self.router_thread.start()

        while not self.stopped.is_set():
            try:
                ready = dict(poller.poll(500))
                if dispatcher in ready:
                    frames = dispatcher.recv()
                    try:
                        session = Session(self.context,
                                          self.router_uri,
                                          session_worker_uri,
                                          frames, self.stopped,
                                          host_resolver=self.host_resolver)
                        self.sessions[session.session_id] = session
                        self.curr_session = session.session_id
                        session.start()
                    except Exception, ex:
                        print '%r' % ex

                if worker in ready:
                    frames = worker.recv_multipart()
                    data = msgpack.unpackb(frames[2])
                    if frames[0] != self.curr_session:
                        continue
                    if len(data) > 4 and data[0] != 'FINISHED':
                        # PIPE
                        dispatcher.send_multipart(list(stringify(*data)))
                    else:
                        dispatcher.send_multipart(list(stringify(*data)))
            except zmq.ZMQError:
                break

        LOGC.debug("Exiting local dispatcher")
        dispatcher.close()

    def consume_queue(self, endp_type, ident=None, *args, **kwargs):
        if endp_type not in self.endpoints:
            raise Exception("Invalid queue type: %s" % endp_type)
        try:
            uri = self.endpoints[endp_type][1]
            sock = self.context.socket(zmq.DEALER)
            if ident:
                sock.setsockopt(zmq.IDENTITY, ident)
            sock.connect(uri)
        except zmq.ZMQError, zerr:
            if getattr(zerr, 'errno', 0) == 93:
                # wrong protocol
                raise Exception(
                    "Wrong connection uri: %s" % uri)
            if getattr(zerr, 'errno', 0) == 2:
                # wrong protocol
                raise Exception("Socket uri is not accessible: %s" % uri)
            else:
                LOGC.exception(zerr)

        self._sockets.append(sock)
        return SockWrapper(uri, sock)

    def publish_queue(self, endp_type, ident=None, *args, **kwargs):
        # wait for ssl init
        self.ssl_init_event.wait(2)

        if endp_type not in self.endpoints:
            raise Exception("Invalid queue type: %s" % endp_type)
        try:
            sock = self.context.socket(zmq.DEALER)
            uri = self.endpoints[endp_type][1]
            if ident:
                sock.setsockopt(zmq.IDENTITY, ident)
            sock.connect(uri)
        except zmq.ZMQError, zerr:
            if getattr(zerr, 'errno', 0) == 93:
                # wrong protocol
                raise Exception(
                    "Wrong connection uri: %s" % uri)
            if getattr(zerr, 'errno', 0) == 2:
                # wrong protocol
                raise Exception("Socket uri is not accessible: %s" % uri)
            else:
                LOGC.exception(zerr)

        self._sockets.append(sock)
        return SockWrapper(uri, sock)

    def create_poller(self, *sockets):
        return PollerWrapper(*sockets)

    def terminate(self, force=False):
        self.stopped.set()
        self.ssl_thread_event.set()
        ioloop.IOLoop.instance().stop()

        for sock in self._sockets:
            if force:
                sock.close(0)
            else:
                sock.close()
        if force:
            try:
                self.context.term()
            except KeyboardInterrupt:
                exit(0)

    def configure(self, overwrite=False, **kwargs):
        config = Config(CONFIG_SHELL_LOC)

        if (config.security.ssl_cert and
                os.path.exists(config.security.ssl_cert) and not overwrite):
            print("Current configuration already exists. "
                  "Use the --overwrite "
                  "option to create new configuration")
            exit(2)

        conf_dir = os.path.join(LIB_DIR, "cloudrunner-cli")
        key_size = int(config.security.key_size or 2048)
        cert_dir = os.path.join(conf_dir, 'certs')
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        if not config.security.peer_cache:
            self.peer_cache = os.path.join(conf_dir, 'peer_cache.db')
            config.update("Security", "peer_cache", self.peer_cache)
            # Create
            CertStore(self.peer_cache)

        if not config.host_resolver:
            host_resolver_file = os.path.join(conf_dir, 'host_resolver.conf')
            try:
                # Create
                config.update("General",
                              "host_resolver",
                              host_resolver_file)
            except Exception, ex:
                print "ERR", ex
                pass

        ssl_cert = os.path.join(cert_dir, 'cloudrunner.crt')
        ssl_key = os.path.join(cert_dir, 'cloudrunner.key')
        cert_pass = ''.join([random.choice(ascii_letters)
                             for x in range(32)])

        key = m.EVP.PKey()
        rsa = m.RSA.gen_key(key_size, 65537, lambda: True)
        key.assign_rsa(rsa)
        rsa = None

        req = m.X509.Request()
        req.set_pubkey(key)
        req.set_version(2)

        subj = req.get_subject()
        subj.CN = gethostname()

        # req.sign(key, 'sha1')

        # Self-sign the certificate
        x509 = m.X509.X509()
        x509.set_version(2)
        x509.set_serial_number(1)

        now_t = long(time.time()) + time.timezone
        ASN1_after = m.ASN1.ASN1_UTCTIME()
        ASN1_after.set_time(now_t)
        x509.set_not_before(ASN1_after)

        ASN1_before = m.ASN1.ASN1_UTCTIME()
        ASN1_before.set_time(now_t + 10 * 60 * 60 * 24 * 365)
        x509.set_not_after(ASN1_before)

        x509.set_pubkey(pkey=key)

        x509.set_subject(subj)

        issuer = m.X509.X509_Name()
        issuer.CN = subj.CN
        x509.set_issuer(issuer)
        x509.set_pubkey(key)
        x509.set_pubkey(x509.get_pubkey())  # Assert get/set work
        x509.sign(key, 'sha1')

        key.save_key(ssl_key, callback=lambda x: cert_pass)
        x509.save_pem(ssl_cert)

        config.update('Security', 'ssl_cert', ssl_cert)
        config.update('Security', 'ssl_key', ssl_key)
        config.update('Security', 'cert_pass', cert_pass)

        if not config.plugins.items():
            # No plugins yet
            config.update('Plugins', 'state',
                          "cloudrunner.plugins.state.functions")

        config.reload()

        print "Configuration succeeded"


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

if __name__ == "__main__":
    zmc = ZmqCliTransport()
