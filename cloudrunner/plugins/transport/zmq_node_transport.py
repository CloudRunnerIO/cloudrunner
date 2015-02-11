#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# /*******************************************************
#  * Copyright (C) 2013-2014 CloudRunner.io <info@cloudrunner.io>
#  *
#  * Proprietary and confidential
#  * This file is part of CloudRunner Server.
#  *
#  * CloudRunner Server can not be copied and/or distributed
#  * without the express permission of CloudRunner.io
#  *******************************************************/

import httplib
import logging
import M2Crypto as m
import os
import platform
import random
import socket
import stat
from string import ascii_letters
from socket import gethostname
from threading import Thread
from threading import Event
import time
import zmq
from zmq.eventloop import ioloop
import uuid

from cloudrunner import LIB_DIR, CONFIG_NODE_LOCATION
from cloudrunner.version import VERSION
from cloudrunner.core.message import *  # noqa
from cloudrunner.util.aes_crypto import Crypter
from cloudrunner.util.config import Config
from cloudrunner.util.decorators import catch_ex
from cloudrunner.util.net import get_ips
from cloudrunner.util.shell import colors, Timer
from cloudrunner.util.psutil_wrapper import psutil
from cloudrunner.util.tlszmq import TLSZmqClientSocket
from cloudrunner.plugins.transport.base import TransportBackend


from cloudrunner.plugins.transport.zmq_transport import (SockWrapper,
                                                         PollerWrapper)
LOGC = logging.getLogger('ZMQ+SSL Node Transport')
STATE_OPS = ("IDENT", "RELOAD", 'FINISHED')


class NodeTransport(TransportBackend):

    proto = 'zmq+ssl'

    config_options = ["node_id", "master_pub", "master_repl",
                      "worker_count", "sock_dir", "security.node_csr",
                      "security.server", "security.node_cert",
                      "security.node_key", "security.ca", "security.cert_pass"]

    def __init__(self, node_id=None, master_pub=None, master_repl=None,
                 worker_count=5, sock_dir=None, node_cert=None, node_key=None,
                 ca=None, server=None, node_csr=None, ping_master=None,
                 cert_pass=None, **kwargs):
        self.node_id = node_id or socket.gethostname()
        self.worker_count = worker_count
        self.master_pub = master_pub
        self.master_repl = master_repl
        self.wait_for_approval = int(kwargs.get('wait_for_approval', 120))
        self._sockets = []
        self.context = zmq.Context()
        self.ssl_thread_event = Event()
        self.stopped = Event()
        self.node_cert = node_cert
        self.node_key = node_key
        self.ca = ca
        self.server = server
        self.node_csr = node_csr
        self.cert_pass = cert_pass
        self.sock_dir = sock_dir
        self.ping_master = ping_master
        self.properties.append(('Backend type', self.proto))
        if self.node_cert and \
                os.path.exists(self.node_cert):
            try:
                node_crt = m.X509.load_cert(self.node_cert)
                self.properties.append(('Node cert fingerprint',
                                        node_crt.get_fingerprint('sha1')))
                self.properties.append(('Node cert subject',
                                        str(node_crt.get_subject())))
                self.properties.append(('Node cert issuer',
                                        str(node_crt.get_issuer().CN)))
                org = node_crt.get_subject().O
                if org:
                    self.properties.append(('Organization', org))
            except:
                pass

    def meta(self):
        if not hasattr(self, '_meta') or not self._meta:
            meta = {}
            try:
                meta['ID'] = self.node_id
                meta['SERVER_NAME'] = socket.gethostname()
                meta['MASTER_IP'] = self.master_pub.partition(':')[0]

                meta['HOST'] = gethostname().lower()
                meta['OS'] = platform.system()
                meta['ARCH'] = platform.machine()
                try:
                    # only OS, not version
                    meta['DIST'] = platform.linux_distribution()[0]
                    if not meta['DIST']:
                        # Try a hack for ArchLinux
                        meta['DIST'] = platform.linux_distribution(
                            # only OS, not version
                            supported_dists=('arch'))[0]
                except:
                    # Python < 2.6
                    meta['DIST'] = platform.dist()[0]  # only OS, not version
                meta['RELEASE'] = platform.release()
                meta['PUBLIC_IP'] = []
                meta['PRIVATE_IP'] = []
                try:
                    meta['PUBLIC_IP'], meta['PRIVATE_IP'] = get_ips()
                except:
                    pass
                if not meta['PUBLIC_IP'] and not meta['PRIVATE_IP']:
                    LOG.warn("No IPs were detected")

                mem = psutil.virtual_memory()
                meta['TOTAL_MEM'] = mem.total / (1024 * 1024)
                meta['AVAIL_MEM'] = mem.available / (1024 * 1024)
                meta['CPU_CORES'] = psutil.cpu_count()
                meta['CPUS'] = psutil.cpu_count(logical=False)

                meta['CRN_VER'] = VERSION
                self._meta = meta
            except:
                self._meta = {}
        return self._meta

    def usage(self):
        usage = {}
        try:
            mem = psutil.virtual_memory()
            usage['TOTAL_MEM'] = mem.total / (1024 * 1024)
            usage['AVAIL_MEM'] = mem.available / (1024 * 1024)
            usage['FREE_MEM'] = mem.free / (1024 * 1024)
            usage['CPU_USAGE'] = psutil.cpu_percent()
            cpu_perc = psutil.cpu_times_percent()
            usage['CPU_TIMES_IDLE'] = cpu_perc.idle
            usage['CPU_TIMES_SYS'] = cpu_perc.system
            usage['CPU_TIMES_USER'] = cpu_perc.user
        except:
            pass
        return usage

    def loop(self):
        try:
            ioloop.IOLoop.instance().start()
        except KeyboardInterrupt:
            ioloop.IOLoop.instance().stop()

    def _ssl_socket_device(self, context):
        LOGC.info("Starting new SSL thread")
        args = []
        kwargs = {}
        if self.node_cert and \
                os.path.exists(self.node_cert):
            # We have issued certificate
            args.append(self.node_cert)
            args.append(self.node_key)
            kwargs['ca'] = self.ca
            kwargs['cert_password'] = self.cert_pass

        ssl_socket = TLSZmqClientSocket(self.context,
                                        self.buses['jobs'][0],
                                        self.endpoints['ssl-proxy'],
                                        self.ssl_thread_event,
                                        route_packets=False,
                                        bind_socket=False,
                                        *args, **kwargs)
        ssl_socket.start()

        ssl_socket.shutdown()
        LOGC.info("Exited SSL thread")

    @catch_ex("Cannot prepare backend, check configuration. Error: {1}")
    def prepare(self):
        LOGC.debug("Starting ZMQ Transport")

        # check in order: args, kwargs, config
        master_sub = 'tcp://%s' % self.master_pub
        master_reply_uri = 'tcp://%s' % self.master_repl
        # worker_count = int(self.worker_count or 5)

        sock_dir = self.sock_dir or os.path.join(LIB_DIR,
                                                 'cloudrunner', 'sock')
        if not os.path.exists(sock_dir):
            os.makedirs(sock_dir)

        if os.name == 'nt':
            control_uri = 'tcp://127.0.0.1:54112'
            ssl_proxy_uri = 'tcp://127.0.0.1:54112'
            int_proxy = 'tcp://127.0.0.1:54113'
        else:
            control_uri = 'inproc://control-queue.sock'
            # ssl_proxy_uri = 'inproc://ssl-proxy-queue.sock'
            ssl_proxy_uri = 'ipc://%s/ssl-proxy-queue.sock' % sock_dir
            int_proxy = 'inproc://int-proxy-queue.sock'

        self.endpoints = {'ssl-proxy': ssl_proxy_uri,
                          'internal-proxy': int_proxy}
        self.buses = {
            'requests': [master_sub, control_uri],
            'jobs': [master_reply_uri, ssl_proxy_uri],
        }

        if not self.node_key or not os.path.exists(self.node_key):
            LOGC.warn('Client key not generated, run program '
                      'with "configure" option first.')
            exit(1)

        # Run worker threads
        LOGC.info('Running client in server mode')
        listener = Thread(target=self.listener_device)
        listener.start()

        if not os.path.exists(self.node_cert):
            csreq = self.node_csr
            if not csreq:
                base_name = self.node_key.rpartition('.')[0]
                csreq = '.'.join(base_name, ".csr")
                if not os.path.exists(csreq):
                    LOGC.warn(
                        'Client certificate request not found.'
                        'Run program with "configure" option first or set'
                        ' the path to the .csr file in the config as:\n'
                        '[Security]\n'
                        'node_csr=path_to_file\n')
                    exit(1)

            if not self._register():
                LOGC.error("Cannot register node at master")
                return False
            else:
                return True  # SSL already started

        self.ssl_start()

        if self.ping_master:
            int_proxy = self.context.socket(zmq.DEALER)
            int_proxy.connect(self.endpoints['internal-proxy'])
            self._sockets.append(int_proxy)

            def _ping_master():
                try:
                    int_proxy.send_multipart(['SSL_PROXY', Ping()._])
                except Exception, ex:
                    LOGC.exception(ex)

            self.timer = Timer(10, _ping_master)
            self.timer.start()

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
                LOGC.exception(zerr)

        wrap = SockWrapper(uri, sock)
        self._sockets.append(wrap)
        return wrap

    publish_queue = consume_queue

    def create_poller(self, *sockets):
        return PollerWrapper(*sockets)

    def decrypt(self, message):
        return self.decrypter.decrypt(message)

    def listener_device(self):
        self.sub = []
        dispatcher = self.context.socket(zmq.ROUTER)
        dispatcher.bind(self.buses['requests'][1])

        ssl_proxy = self.context.socket(zmq.ROUTER)
        ssl_proxy.bind(self.endpoints['ssl-proxy'])

        master_sub = self.context.socket(zmq.SUB)
        master_sub.setsockopt(zmq.SUBSCRIBE, uuid.uuid4().hex)
        master_sub.connect(self.buses['requests'][0])

        poller = zmq.Poller()
        poller.register(master_sub, zmq.POLLIN)
        poller.register(ssl_proxy, zmq.POLLIN)

        if self.ping_master:
            int_proxy = self.context.socket(zmq.ROUTER)
            int_proxy.bind(self.endpoints['internal-proxy'])
            poller.register(int_proxy, zmq.POLLIN)

        # Syndicate requests from two endpoints and forward to 'requests'
        time.sleep(0.5)
        ssl_proxy.send_multipart(['SSL_PROXY',
                                  HBR(self.node_id, usage=self.usage())._])
        while not self.stopped.is_set():
            try:
                ready = dict(poller.poll(1000))
                if master_sub in ready:
                    _, m = master_sub.recv_multipart()
                    try:
                        message = M.build(m)
                    except Exception, ex:
                        LOGC.error(ex)
                        LOGC.warn(m)
                        continue

                    if isinstance(message, Welcome) or \
                            isinstance(message, Reload):
                        ssl_proxy.send_multipart(
                            ['SSL_PROXY', Ident(meta=self.meta())._])
                    elif isinstance(message, HB):
                        # Heartbeat
                        ssl_proxy.send_multipart(
                            ['SSL_PROXY', HBR(self.node_id,
                                              usage=self.usage())._])
                    elif isinstance(message, Crypto):
                        # decrypt
                        try:
                            msg = self.decrypt(message.message)
                            dispatcher.send_multipart(['DISPATCHER', msg])
                        except Exception, ex:
                            LOGC.error(
                                "Cannot decrypt frames%r" % ex)
                if ssl_proxy in ready:
                    src, packed = ssl_proxy.recv_multipart()
                    if src == "SSL_PROXY":
                        # SSL proxy -> Session
                        msg = M.build(packed)
                        if isinstance(msg, Init):
                            # ToDo: better command handler
                            sub_loc = msg.org_id
                            if sub_loc not in self.sub:
                                self.sub.append(sub_loc)
                                master_sub.setsockopt(zmq.SUBSCRIBE, sub_loc)
                                LOGC.info("Listening to %s" % msg.org_name)
                            LOGC.info("Resetting crypter keys")
                            self.decrypter = Crypter(msg.session_key,
                                                     msg.session_iv)
                        elif isinstance(msg, Job):
                            try:
                                LOGC.info(vars(msg))
                                # FWD to Session
                                ssl_proxy.send_multipart(
                                    [msg.hdr.dest, msg._])
                            except Exception, ex:
                                LOGC.error(
                                    "Cannot decrypt frames %r" % ex)
                        if isinstance(msg, Control):
                            ssl_proxy.send_multipart(["REGISTER", msg._])
                    elif src == "REGISTER":
                        msg = M.build(packed)
                        if isinstance(msg, Register):
                            ssl_proxy.send_multipart(['SSL_PROXY', msg._])
                        elif isinstance(msg, Reload):
                            ssl_proxy.send_multipart(
                                ['SSL_PROXY', Ident(meta=self.meta())._])
                    else:
                        # Session -> SSL proxy
                        ssl_proxy.send_multipart(['SSL_PROXY', packed])
                if self.ping_master and int_proxy in ready:
                    _, src, packed = int_proxy.recv_multipart()
                    msg = M.build(packed)
                    if isinstance(msg, Ping):
                        # Ping
                        ssl_proxy.send_multipart(['SSL_PROXY', msg._])
            except KeyboardInterrupt:
                LOGC.info('Exiting node listener thread')
                break
            except zmq.ZMQError, zerr:
                if zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                        or zerr.errno == zmq.ENOTSOCK:
                    break
                LOGC.exception(zerr)
            except Exception, ex:
                LOGC.error("Node listener thread: exception")
                LOGC.exception(ex)

        ssl_proxy.close()

        for sub_loc in self.sub:
            master_sub.setsockopt(zmq.UNSUBSCRIBE, sub_loc)
        master_sub.close()
        dispatcher.close()
        LOGC.info('Node Listener exited')

    def _register(self):

        LOGC.info(colors.red('Registering on Master...'))
        csreq = self.node_csr
        _config = Config(CONFIG_NODE_LOCATION)
        try:
            csreq_data = open(csreq).read()
        except Exception, ex:
            LOGC.error(colors.red('Cannot read %s file' % csreq))
            return False

        csr = None
        try:
            csr = m.X509.load_request(csreq)
            node_id = csr.get_subject().CN
        except Exception, ex:
            LOGC.error(
                "%s doesn't seem to be a valid certificate file" % csreq)
            LOGC.exception(ex)
            return False
        finally:
            if csr:
                del csr

        start_reg = time.time()

        def _next(reply):
            if not reply:
                # First call? Send CSR
                return Register(node_id, csreq_data, meta=self.meta())

            msg = Control.build(reply)
            if not msg:
                return -1

            if msg.status == "APPROVED":
                # Load certificates from chain
                (node_crt_string,
                 ca_crt_string,
                 server_crt_string) = msg.message.split(
                     TOKEN_SEPARATOR)

                node_cert = m.X509.load_cert_string(
                    str(node_crt_string), m.X509.FORMAT_PEM)
                ca_cert = m.X509.load_cert_string(
                    str(ca_crt_string), m.X509.FORMAT_PEM)
                server_cert = m.X509.load_cert_string(
                    str(server_crt_string), m.X509.FORMAT_PEM)

                # First verify if the cert matches the request
                csr = m.X509.load_request_string(csreq_data)
                node_key_priv = m.RSA.load_key(
                    self.node_key,
                    lambda x: self.cert_pass)

                node_key = m.EVP.PKey()
                node_key.assign_rsa(node_key_priv)
                node_cert.set_pubkey(node_key)

                assert csr.verify(node_cert.get_pubkey()), \
                    "Certificate request failed to verify node cert"
                assert node_cert.verify(ca_cert.get_pubkey()), \
                    "Node cert failed to verify CA cert"

                crt_file_name = self.node_cert
                node_cert.save_pem(crt_file_name)
                os.chmod(crt_file_name, stat.S_IREAD | stat.S_IWRITE)
                del node_key
                del node_cert
                del csr

                if not self.ca:
                    base = os.path.dirname(os.path.abspath(crt_file_name))
                    _config.update('Security', 'ca',
                                   os.path.join(base, 'ca.crt'))

                open(_config.security.ca, 'w').write(str(ca_crt_string))
                self.ca = _config.security.ca

                os.chmod(_config.security.ca, stat.S_IREAD | stat.S_IWRITE)
                del ca_cert

                if not _config.security.server:
                    base = os.path.dirname(os.path.abspath(crt_file_name))
                    _config.update('Security', 'server',
                                   os.path.join(base, 'server.crt'))

                server_cert.save_pem(_config.security.server)
                self.server = _config.security.server
                os.chmod(_config.security.server,
                         stat.S_IREAD | stat.S_IWRITE)
                del server_cert

                LOGC.info('Master approved the node. Starting service')
                return 0
            elif msg.status == "REJECTED":
                if msg.message == 'SEND_CSR':
                    # resend
                    return Register(node_id, csreq_data, meta=self.meta())
                if msg.message == 'PENDING':
                    LOGC.info("Master says: Request queued for approval.")
                    if time.time() < start_reg + int(self.wait_for_approval):
                        time.sleep(10)  # wait 10 sec before next try
                        return Register(node_id, csreq_data, meta=self.meta())
                    else:
                        return -1
                elif msg.message == 'ERR_CRT_EXISTS':
                    LOGC.info(
                        'Master says: "There is already an issued certificate'
                        ' for this node. Remove the certificate'
                        ' from master first"')
                    return -1
                elif msg.message == 'ERR_CN_FAIL':
                    LOGC.info(
                        'Master says: "Node Id doesn\'t match the request CN"')
                    return -1
                elif msg.message == 'INV_CSR':
                    LOGC.info('Master says: "Invalid CSR file"')
                    return -1
                elif msg.message == 'ERR_NAME_FORBD':
                    csr = m.X509.load_request_string(csreq_data)
                    LOGC.info(
                        'Master says: "The chosen node name(CN) - [%s] is '
                        'forbidden. Choose another one."' %
                        csr.get_subject().CN)
                    del csr
                    return -1
                elif msg.message == 'APPR_FAIL':
                    LOGC.info('Master says: "Certificate approval failed"')
                    return -1
                elif msg.message == 'QUOTA_FAIL':
                    LOGC.info('Master says: "Node quota exceeded"')
                    return -1
                else:
                    LOGC.info('Master says: "%s"' % msg.message)
                    return -1
            else:
                return -1

        reply = None
        approved = False

        self.ssl_start()

        reg_sock = self.context.socket(zmq.DEALER)
        reg_sock.setsockopt(zmq.IDENTITY, "REGISTER")
        reg_sock.connect(self.endpoints['ssl-proxy'])

        while not self.stopped.is_set():
            try:
                next_rq = _next(reply)
                if next_rq == -1:
                    break
                if next_rq == 0:
                    # We're done, go ahead
                    approved = True
                    self.restart()
                    time.sleep(.5)  # wait for sockets to start
                    reg_sock.send(Reload()._)
                    break
                else:
                    end_wait = \
                        start_reg + int(self.wait_for_approval) - time.time()

                    reg_sock.send(next_rq._)
                    if not reg_sock.poll(end_wait * 1000):
                        LOGC.error("Timeout waiting for register response")
                        break
                    reply = reg_sock.recv()
            except zmq.ZMQError, zerr:
                if zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                        or zerr.errno == zmq.ENOTSOCK:
                    break
                LOGC.exception(zerr)
                LOGC.error("Rebuilding ssl connection %s" % reply)
                self.restart()
                reply = next_rq
            except Exception, ex:
                LOGC.error(ex)
                break

        reg_sock.close(0)
        return approved

    def ssl_start(self):
        self.ssl_thread = Thread(target=self._ssl_socket_device,
                                 args=[self.context])
        self.ssl_thread.start()
        time.sleep(.5)  # wait for sockets to start

    def ssl_stop(self):
        self.ssl_thread_event.set()
        if hasattr(self, 'ssl_thread'):
            self.ssl_thread.join(1)
        self.ssl_thread_event.clear()

    def restart(self):
        LOGC.info('Restarting SSL Client')
        self.ssl_stop()
        self.ssl_start()
        LOGC.info('SSL Client restarted')

    def terminate(self):
        LOGC.info("Received terminate signal")
        if self.ping_master:
            self.timer.stop()
        self.stopped.set()
        self.ssl_stop()
        ioloop.IOLoop.instance().stop()
        for sock in self._sockets:
            sock.close()
        LOGC.info('Node transport closed')

    def configure(self, overwrite=False, **kwargs):
        config = Config(CONFIG_NODE_LOCATION)
        conf_dir = os.path.join(LIB_DIR, "cloudrunner_node")
        key_size = int(config.security.key_size or 2048)
        if kwargs.get("node_id"):
            self.node_id = kwargs["node_id"]

        cert_dir = os.path.join(conf_dir, 'certs')
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        key_file = config.security.node_key
        if not key_file or os.path.exists(key_file):
            if not overwrite:
                print("Node key file already exists in your config. "
                      "If you want to create new one - run\n"
                      "\tcloudrunner-node configure --overwrite\n"
                      "IMPORTANT! Please note that regenerating your key "
                      "and certificate will prevent the node from "
                      "connecting to the Master, if it already has "
                      "an approved certificate!")
                return False

        crt_file = config.security.node_cert
        if not crt_file or os.path.exists(crt_file):
            if not overwrite:
                print("Node certificate file already exists in your config. "
                      "If you still want to create new one - run\n"
                      "\tcloudrunner-node configure --overwrite\n"
                      "IMPORTANT! Please note that regenerating your key "
                      "and certificate will prevent the node from "
                      "connecting to the Master, if it already has "
                      "an approved certificate!")
                return False

        cert_password = ''.join([random.choice(ascii_letters)
                                 for x in range(32)])

        key_file = os.path.join(cert_dir, '%s.key' % self.node_id)
        csr_file = os.path.join(cert_dir, '%s.csr' % self.node_id)
        crt_file = os.path.join(cert_dir, '%s.crt' % self.node_id)

        node_key = m.EVP.PKey()

        rsa = m.RSA.gen_key(key_size, 65537, lambda: True)
        node_key.assign_rsa(rsa)
        rsa = None

        print("Saving KEY file %s" % key_file)
        node_key.save_key(key_file, callback=lambda x: cert_password)
        os.chmod(key_file, stat.S_IREAD | stat.S_IWRITE)

        req = m.X509.Request()
        req.set_pubkey(node_key)
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

        subj.CN = self.node_id
        if config.use_meta_id:
            subj.OU = self.get_meta_data()
        else:
            subj.OU = kwargs.get("org") or "DEFAULT"

        if kwargs.get('tags') and isinstance(kwargs['tags'], list):
            for tag in kwargs['tags']:
                subj.GN = tag
        req.sign(node_key, 'sha1')
        assert req.verify(node_key)
        assert req.verify(req.get_pubkey())

        print("Subject %s" % subj)
        print("Saving CSR file %s" % csr_file)
        req.save_pem(csr_file)
        os.chmod(csr_file, stat.S_IREAD | stat.S_IWRITE)

        print('Generation of credentials is complete.'
              'Now run cloudrunner-node to register at Master')

        if os.path.exists(crt_file):
            # if crt file exists - remove it, as it cannot be used
            # anymore with the key file
            os.unlink(crt_file)
        print("Updating config settings")
        config.update('General', 'node_id', self.node_id)
        config.update('General', 'work_dir',
                      os.path.join(conf_dir, 'tmp'))

        if kwargs.get("server_uri"):
            ip = kwargs.get("server_uri")
            config.update('General', 'master_pub', "%s:5551" % ip)
            config.update('General', 'master_repl', "%s:5552" % ip)

        config.update('Security', 'cert_path', cert_dir)
        config.update('Security', 'node_key', key_file)
        config.update('Security', 'node_csr', csr_file)
        config.update('Security', 'node_cert', crt_file)
        config.update('Security', 'cert_pass', cert_password)
        config.update('Security', 'ca', '')
        config.update('Security', 'server', '')
        config.reload()

    def get_meta_data(self):
        address = '169.254.169.254'
        conn = httplib.HTTPConnection(address, timeout=5)

        def openstack():
            path = '/openstack/2013-04-04/meta_data.json'
            try:
                conn.request('GET', path)
                res = conn.getresponse()
                if res.status == 200:
                    # OpenStack cloud
                    return json.loads(res.read()).get("uuid", 'N/A')
            except Exception, ex:
                LOGC.error(ex)
                return

        def amazon_aws():
            path = '/2012-01-12/meta-data/instance-id'
            try:
                conn.request('GET', path)
                res = conn.getresponse()
                if res.status == 200:
                    # AmazonAWS cloud
                    return res.read() or "N/A"
            except Exception, ex:
                LOGC.error(ex)
                return

        ret = openstack()
        if not ret:
            ret = amazon_aws()

        return ret
