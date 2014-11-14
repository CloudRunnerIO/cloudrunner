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
import socket
import stat
from string import ascii_letters
from threading import Thread
from threading import Event
import time
import zmq
from zmq.eventloop import ioloop

from cloudrunner.core.message import *  # noqa
from cloudrunner.util.string import stringify


from cloudrunner import LIB_DIR
from cloudrunner import CONFIG_NODE_LOCATION
from cloudrunner.plugins.transport.base import TransportBackend
from cloudrunner.plugins.transport.zmq_transport import (SockWrapper,
                                                         PollerWrapper)
from cloudrunner.util.config import Config
from cloudrunner.util.cert_store import CertStore
from cloudrunner.util.tlszmq import TLSZmqServerSocket

LOGC = logging.getLogger('ZMQ Node Transport')
STATE_OPS = ("IDENT", "RELOAD", 'FINISHED')


class NodeTransport(TransportBackend):

    """
    Single-user node transport
    """
    proto = 'zmq+ssl'

    config_options = ["node_id", "master_repl",
                      "worker_count", "sock_dir", "user_store",
                      "security.node_cert", "security.node_key", "security.ca",
                      "security.cert_pass"]

    def __init__(self, node_id, master_repl, worker_count=5,
                 sock_dir=None, node_cert=None, node_key=None, ca=None,
                 user_store=None, cert_pass=None, **kwargs):
        self.node_id = node_id or socket.gethostname()
        self.master_repl = 'tcp://%s' % master_repl
        self.worker_count = worker_count
        self.sock_dir = sock_dir or os.path.join(
            LIB_DIR, 'cloudrunner', 'sock')
        self.node_cert = node_cert
        self.node_key = node_key
        self.ca = ca
        self.cert_pass = cert_pass
        self._sockets = []
        self.context = zmq.Context()
        self.stopped = Event()
        if not user_store:
            user_store = os.path.join(LIB_DIR, 'cloudrunner', 'user_store.db')
        self.user_store = CertStore(user_store)

    def meta(self):
        return {}

    def loop(self):
        ioloop.IOLoop.instance().start()

    def prepare(self):
        LOGC.debug("Starting ZMQ Transport")

        if not os.path.exists(self.sock_dir):
            os.makedirs(self.sock_dir)

        if os.name == 'nt':
            req_queue_uri = 'tcp://127.0.0.1:54111'
            job_queue_uri = 'tcp://127.0.0.1:54112'
            ssl_proxy_uri = 'tcp://127.0.0.1:54114'
        else:
            req_queue_uri = 'inproc://req-queue.sock'
            job_queue_uri = 'inproc://job-queue.sock'
            ssl_proxy_uri = 'inproc://ssl-proxy-uri'

        self.buses = {
            'requests': ['', req_queue_uri],
            'jobs': [ssl_proxy_uri, ssl_proxy_uri],
            'ssl_proxy': [self.master_repl, ssl_proxy_uri],
            'router': [job_queue_uri, '']
        }

        # Run worker threads
        LOGC.info('Running client in direct mode')
        LOGC.info("Master socket: %s" % self.master_repl)
        listener = Thread(target=self.listener_device)
        listener.start()

        self.main_sock = self.context.socket(zmq.ROUTER)
        self.main_sock.bind(self.buses['ssl_proxy'][0])

        def verify_client(x509, *args):
            subj = x509.get_subject()
            cn = str(subj.CN)
            fprint = x509.get_fingerprint('sha1')
            # find user:fprint in local cache
            if (cn, fprint) in self.user_store:
                return True
            return False

        self.ssl_socket = TLSZmqServerSocket(
            self.main_sock,
            self.buses['router'][0],
            self.node_cert,
            self.node_key,
            cert_password=self.cert_pass,
            route_packets=True,
            verify_func=verify_client)

        def ssl_proxy():
            # Runs the SSL Thread
            while not self.stopped.is_set():
                try:
                    self.ssl_socket.start()  # Start TLSZMQ server socket
                except zmq.ZMQError, zerr:
                    if (zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP
                            or zerr.errno == zmq.ENOTSOCK):
                        # System interrupt
                        break
                except KeyboardInterrupt:
                    break
                except Exception, ex:
                    LOGR.exception(ex)

        t = Thread(target=ssl_proxy)
        t.start()

        return True

    def consume_queue(self, endp_type, ident=None, *args, **kwargs):
        if endp_type not in self.buses:
            raise Exception("Invalid queue type: %s" % endp_type)
        uri = self.buses[endp_type][1]
        try:
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
                raise Exception("Socket uri is not accessible: %s" %
                                uri)
            else:
                LOGC.error("Cannot connect to %s" % uri)
                LOGC.error(zerr)

        wrap = SockWrapper(uri, sock)
        self._sockets.append(wrap)
        return wrap

    publish_queue = consume_queue

    def create_poller(self, *sockets):
        return PollerWrapper(*sockets)

    def listener_device(self):
        dispatcher = self.context.socket(zmq.DEALER)
        dispatcher.setsockopt(zmq.IDENTITY, 'REQ')
        dispatcher.connect(self.buses['router'][0])

        job_router = self.context.socket(zmq.ROUTER)
        job_router.bind(self.buses['jobs'][1])

        reqs = self.context.socket(zmq.DEALER)
        reqs.bind(self.buses['requests'][1])

        poller = zmq.Poller()
        poller.register(dispatcher, zmq.POLLIN)
        poller.register(job_router, zmq.POLLIN)
        # Syndicate requests from two endpoints and forward to 'requests'
        session_map = {}
        while not self.stopped.is_set():
            try:
                ready = dict(poller.poll(100))
                if dispatcher in ready:
                    data = dispatcher.recv_multipart()
                    peer = data.pop(0)
                    session_id = data[0]
                    session_map[session_id] = peer
                    if len(data) == 2:
                        reqs.send_multipart(list(stringify(*data)))
                    elif len(data) == 3:
                        job_router.send_multipart(list(stringify(*data)))
                    else:
                        LOGC.warn("Unknown request: %s" % data)
                if job_router in ready:
                    frames = job_router.recv_multipart()
                    peer = session_map.get(frames.pop(0)) or ''
                    if peer:
                        frames.insert(1, self.node_id)
                        dispatcher.send_multipart(
                            [peer, msgpack.packb(frames)])
            except KeyboardInterrupt:
                LOGC.info('Exiting node listener thread')
                break
            except zmq.ZMQError, zerr:
                if (zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP
                        or zerr.errno == zmq.ENOTSOCK):
                    break
                LOGC.exception(zerr)
                LOGC.error(zerr.errno)
            except Exception, ex:
                LOGC.exception("Node listener thread: exception %s" % ex)

        dispatcher.close()
        reqs.close()
        job_router.close()
        LOGC.info('Node Listener exited')

    def terminate(self):
        LOGC.info("Received terminate signal")
        self.stopped.set()
        self.ssl_socket.terminate()
        ioloop.IOLoop.instance().stop()
        for sock in self._sockets:
            sock.close()
        self.context.term()
        LOGC.info('Node transport closed')

    def configure(self, overwrite=False, **kwargs):

        config = Config(CONFIG_NODE_LOCATION)
        conf_dir = os.path.abspath(os.path.dirname(CONFIG_NODE_LOCATION))
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir)

        conf_dir = os.path.join(LIB_DIR, "cloudrunner_node")
        key_size = int(config.security.key_size or 2048)

        cert_dir = os.path.join(conf_dir, 'certs')
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        key_file = config.security.node_key
        if key_file and os.path.exists(key_file) and not overwrite:
            print("Node key file already exists in your config. "
                  "If you want to create new one - run\n"
                  "\tcloudrunner-node configure --overwrite\n"
                  "IMPORTANT! Please note that regenerating your key "
                  "and certificate will prevent the node from "
                  "connecting to the Master, if it already has "
                  "an approved certificate!")
            exit(2)

        crt_file = config.security.node_cert
        if crt_file and os.path.exists(crt_file) and not overwrite:
            print("Node certificate file already exists in your config. "
                  "If you still want to create new one - run\n"
                  "\tcloudrunner-node configure --overwrite\n"
                  "IMPORTANT! Please note that regenerating your key "
                  "and certificate will prevent the node from "
                  "connecting to the Master, if it already has "
                  "an approved certificate!")
            exit(2)

        cert_password = ''.join([random.choice(ascii_letters)
                                 for x in range(32)])

        key_file = os.path.join(cert_dir, '%s.key' % self.node_id)
        crt_file = os.path.join(cert_dir, '%s.crt' % self.node_id)

        key = m.EVP.PKey()

        rsa = m.RSA.gen_key(key_size, 65537, lambda: True)
        key.assign_rsa(rsa)
        rsa = None

        print("Saving KEY file %s" % key_file)
        key.save_key(key_file, callback=lambda x: cert_password)
        os.chmod(key_file, stat.S_IREAD | stat.S_IWRITE)

        req = m.X509.Request()
        req.set_pubkey(key)
        req.set_version(2)

        subj = req.get_subject()

        try:
            import locale
            l_c = locale.getdefaultlocale()
            subj.C = l_c[0].rpartition('_')[-1]
        except:
            pass
        if not subj.C or len(subj.C) != 2:
            subj.C = "US"

        subj.CN = kwargs.get("node_id") or self.node_id
        subj.OU = 'DEFAULT'
        if kwargs.get('tags') and isinstance(kwargs['tags'], list):
            for tag in kwargs['tags']:
                subj.GN = tag

        req.sign(key, 'sha1')
        assert req.verify(key)
        assert req.verify(req.get_pubkey())

        print("Certificate Subject %s" % subj)

        if os.path.exists(crt_file):
            # if crt file exists - remove it, as it cannot be used
            # anymore with the key file
            os.unlink(crt_file)

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

        print("Saving cert file %s" % crt_file)
        x509.save_pem(crt_file)

        print("Updating config settings")
        config.update('General', 'node_id', subj.CN)
        if not kwargs.get("master_repl"):
            config.update('General', 'master_repl', "0.0.0.0:5552")
        if not kwargs.get("user_store"):
            user_store = os.path.join(LIB_DIR, 'cloudrunner', 'user_store.db')
            config.update('General', 'user_store', user_store)
        config.update('General', 'work_dir', os.path.join(conf_dir, 'tmp'))
        config.update('Security', 'node_key', key_file)
        config.update('Security', 'node_cert', crt_file)
        config.update('Security', 'cert_pass', cert_password)

        if not config.plugins.items():
            # No items yet
            config.update('Plugins', 'state',
                          "cloudrunner.plugins.state.functions")
        config.reload()
