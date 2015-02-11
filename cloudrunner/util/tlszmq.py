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
from StringIO import StringIO
import threading
import time
import zmq

from cloudrunner.core.message import M, Quit

LOGS = logging.getLogger('TLSZmq Server')
LOGC = logging.getLogger('TLSZmq Client')
SIGN_DIGEST = 'sha256'


class ConnectionException(Exception):
    pass


class ServerDisconnectedException(Exception):
    pass


class TLSZmqServerSocket(object):
    CRL = []

    def __init__(self, socket, proc_socket_uri, cert, key, ca=None,
                 ssl_proto='sslv3', verify_func=None, cert_password=None,
                 route_packets=False):
        """
        Creates a wrapper over Zmq socket, works only with zmq.ROUTER,
        zmq.DEALER, zmq.REQ sockets

        Arguments:

        socket      --  Zmq socket to wrap.

        proc_socket_uri  --  Zmq socket to send/recv packets
                    for internal processing.

        cert        --  Server certificate - PEM-encoded file (eg. server.crt)

        key         --  Server key - PEM-encoded file(e.g. server.key).

        ca          --  Server CA file for verification of client certificates.
                        PEM-encoded file(e.g. ca.crt).

        ssl_proto   --  SSL/TLS protocol to use. Valid values:
                            'sslv3' and 'tlsv1'

        verify_func  --  Verify function. If a CA Certificate file(s) are
                         passed - use them toverify client certificates.
                         If a function is provided - use it to verify
                         the client certificate.

        cert_password --    Certificate private key password

        """
        self.zmq_socket = socket
        self.proc_socket_uri = proc_socket_uri
        self.proto = ssl_proto
        self.cert = cert
        self.key = key
        self.ca = ca
        self.cert_pass = cert_password
        self.route_packets = route_packets
        self.conns = {}
        self.verify_func = verify_func

    def _update_conn(self, ident, x509):
        if x509 and x509.get_serial_number() not in self.CRL:
            # auth conn
            subj = x509.get_subject()
            client_id = subj.CN
            org_id = subj.O
            self.conns[ident].node = client_id
            self.conns[ident].org = org_id
            return client_id, org_id
        else:
            self.conns[ident].node = None
            # self.conns[ident].org = None
            return None, None

    def start(self):

        class Conn(object):

            def __init__(self, ssl_conn, node, org):
                self.created = time.time()
                self.conn = ssl_conn
                self.node = node
                self.org = org

        if self.route_packets:
            proc_socket = self.zmq_socket.context.socket(zmq.ROUTER)
            proc_socket.bind(self.proc_socket_uri)
        else:
            proc_socket = self.zmq_socket.context.socket(zmq.DEALER)
            proc_socket.connect(self.proc_socket_uri)

        poller = zmq.Poller()
        poller.register(self.zmq_socket, zmq.POLLIN)
        poller.register(proc_socket, zmq.POLLIN)

        def prepare_res(ident, node, org, resp):
            if self.route_packets:
                packets = list(*msgpack.unpackb(resp))
                packets.insert(1, ident)
                return packets  # [ident, resp]
            else:
                return [ident, node, org, resp]

        queue = []
        while True:
            try:
                (ident, enc_req, data) = (None, None, None)
                if queue:
                    _type, ident, val = queue.pop(0)
                    if _type == 1:
                        enc_req = val
                    else:
                        data = val
                else:
                    socks = dict(poller.poll())
                    if self.zmq_socket in socks:
                        # Read from SSL socket
                        packets = self.zmq_socket.recv_multipart(copy=False)
                        # Verify packet size before consuming
                        if len(packets) == 2 and len(packets[0]) <= 32:
                            queue.append((1, packets[0].bytes,
                                          packets[1].bytes))
                        else:
                            LOGS.warn("Invalid data recvd")

                    if proc_socket in socks:
                        # Read from workers
                        frames = proc_socket.recv_multipart()
                        if self.route_packets:
                            frames.pop(0)
                        plain_data = frames[0]
                        hdr, plain_data = M.pop_header(plain_data)
                        queue.append((2, hdr.ident, plain_data))

                if queue and not enc_req and not data:
                    _type, ident, val = queue.pop(0)
                    if _type == 1:
                        enc_req = val
                    else:
                        data = val

                if not ident:
                    continue

                if enc_req == '-255':
                    # Remove me
                    if ident in self.conns:
                        conn = self.conns.pop(ident)
                        LOGS.debug('Removing %s from cache' % vars(conn))
                        m = Quit(conn.node)
                        m.hdr.ident = ident
                        m.hdr.peer = conn.node or ''
                        m.hdr.org = conn.org or ''
                        proc_socket.send(m._)
                        conn.conn.shutdown()
                        continue

                if ident not in self.conns:
                    self.conns[ident] = Conn(
                        TLSZmqServer(ident, self.cert,
                                     self.key, self.ca,
                                     verify_func=self.verify_func,
                                     cert_password=self.cert_pass),
                        None, None)
                    LOGS.debug('Adding new conn %s' % ident)
                LOGS.debug(
                    "Total %s SSL Connection objects" % len(self.conns))
                tls = self.conns[ident].conn

                if enc_req:
                    try:
                        tls.put_data(enc_req)
                        tls.update()
                    except ConnectionException, cex:
                        LOGS.error(cex)
                        continue

                if tls.can_recv():
                    plain_data = tls.recv()
                    client_id = ''
                    org_id = ''
                    try:
                        if self.verify_func:
                            x509 = tls.ssl.get_peer_cert()
                            client_id, org_id = self._update_conn(ident, x509)
                        else:
                            self.conns[ident].node = None
                            self.conns[ident].org = None
                    except Exception, ex:
                        # anon conn
                        self.conns[ident].node = None
                        self.conns[ident].org = None
                        LOGS.exception(ex)

                    LOGS.debug("GOT DATA: %s" % [repr(ident),
                                                 client_id,
                                                 org_id,
                                                 plain_data])

                    header = dict(ident=ident,
                                  peer=client_id,
                                  org=org_id or '')
                    try:
                        plain_data = M.set_header(plain_data, header)
                        LOGS.debug("Repacked msg: %r" % plain_data)
                        proc_socket.send(plain_data)
                    except Exception, ex:
                        LOGS.exception(ex)

                if data:
                    LOGS.debug("Sending SSL DATA: %s" % data)
                    tls.send(data)
                    # LOGS.debug("SENDING DATA: %s" % [repr(ident), data])
                    try:
                        flushed = tls.update()
                        if self.verify_func and flushed and \
                                not self.conns[ident].node:
                            LOGS.debug("Anon connection, dropping %s" %
                                       repr(ident))
                            # Remove cached ssl obj for unauth reqs
                            conn = self.conns.pop(ident)
                            conn.conn.shutdown()
                    except ConnectionException, ex:
                        continue

                if tls.needs_write():
                    enc_rep = tls.get_data()
                    self.zmq_socket.send_multipart([ident, enc_rep])
            except zmq.ZMQError, zerr:
                if zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                        or zerr.errno == zmq.ENOTSOCK:
                    # System interrupt
                    break
            except KeyboardInterrupt:
                break
            except Exception, ex:
                LOGS.exception(ex)
                break

        self.terminate()
        LOGS.info("Server exited")

    def terminate(self):
        self.zmq_socket.close()
        for conn in self.conns.values():
            conn.conn.shutdown()


class TLSZmqClientSocket(object):

    def __init__(self, context, ssl_socket_uri, socket_proc_uri, stopped_event,
                 cert=None, key=None, ssl_proto='sslv3',
                 ca=None, cert_password=None, route_packets=False,
                 bind_socket=True, skip_warnings=False, validate_peer=None,
                 init_event=None):
        """
        Creates a wrapper over Zmq socket, works only with zmq.ROUTER,
        zmq.DEALER, zmq.REQ sockets

        Arguments:

        context     --  ZMQ context

        ssl_socket_uri  --  URI to connect zmq socket to.

        socket_proc_uri --  Socket URI to communicate with caller

        stopped_event   --  Event to listen to

        cert        --  Server certificate - PEM-encoded file (eg. client.crt)

        key         --  Server key - PEM-encoded file(e.g. client.key).

        ssl_proto   --  SSL/TLS protocol to use. Valid values:
                            'sslv3' and 'tlsv1'

        ca          --  CA file for server verification

        cert_password --    Certificate private key password

        route_packets   --  Re-route packets(using zmq.ROUTER) or just forward
                            using zmq.DEALER

        bind_socket     --  Bind or connect to the proxy socket

        validate_peer   --  Function to validate server certificate

        init_event      --  Event to indicate when the socket is initialised

        """
        self.context = context
        self.ssl_socket_uri = ssl_socket_uri
        self.socket_proc_uri = socket_proc_uri
        self.proto = ssl_proto
        self.cert = cert
        self.key = key
        self.ca = ca
        self.cert_password = cert_password
        self.stopped = stopped_event
        self.route_packets = route_packets
        self.init = init_event or threading.Event()
        self.bind_socket = bind_socket
        self.skip_warnings = skip_warnings
        self.validate_peer = validate_peer

    def renew(self):
        LOGC.debug("Renewing SSL client socket")
        if hasattr(self, 'tls'):
            self.tls.shutdown()

        if hasattr(self, 'zmq_socket'):
            self.poller.unregister(self.zmq_socket)
            self.zmq_socket.close()
            del self.zmq_socket

        if self.skip_warnings:
            _TLSZmq._ca_warn = 1

        self.tls = TLSZmqClient(self.proto, self.cert, self.key, ca=self.ca,
                                cert_password=self.cert_password)

        self.zmq_socket = self.context.socket(zmq.DEALER)
        try:
            self.zmq_socket.connect(self.ssl_socket_uri)
        except Exception, ex:
            LOGC.error(
                "Cannot connect to %s: [%s]" % (self.ssl_socket_uri, ex))
            raise
        self.poller.register(self.zmq_socket, zmq.POLLIN)
        self.init.set()

    def recv_from_worker(self):
        if self.route_packets:
            return self.socket_proc.recv_multipart()[1]
        else:
            return self.socket_proc.recv()

    def start(self):
        if self.route_packets:
            self.socket_proc = self.context.socket(zmq.ROUTER)
        else:
            self.socket_proc = self.context.socket(zmq.DEALER)
            self.socket_proc.setsockopt(zmq.IDENTITY, 'SSL_PROXY')
        if self.bind_socket:
            self.socket_proc.bind(self.socket_proc_uri)
        else:
            self.socket_proc.connect(self.socket_proc_uri)

        self.poller = zmq.Poller()
        self.poller.register(self.socket_proc, zmq.POLLIN)
        self.renew()

        retry_count = 5
        while not self.stopped.is_set() and retry_count:
            try:
                socks = dict(self.poller.poll(1000))

                if self.socket_proc in socks:
                    data = self.recv_from_worker()
                    LOGC.debug("Data to send %r" % data)

                    self.tls.send(data)
                    # self.tls.send('\x00')  # separator
                    self.tls.update()

                if not self.init.is_set():
                    continue

                if self.tls.needs_write():
                    enc_msg = self.tls.get_data()
                    self.zmq_socket.send(enc_msg)

                if self.zmq_socket in socks:
                    enc_req = self.zmq_socket.recv()
                    self.tls.put_data(enc_req)
                    try:
                        self.tls.update()
                    except ConnectionException, ex:
                        # Possible SSL crash, try to self-heal
                        LOGC.debug(
                            "SSL transport failed, resending %s" % data)
                        retry_count -= 1
                        LOGC.warn("Retries left: %s" % retry_count)
                        self.renew()
                        self.tls.send(data)
                        self.tls.update()
                    except Exception, ex:
                        LOGC.exception(ex)
                        break

                if self.tls.can_recv():
                    packed = self.tls.recv()
                    LOGC.debug("Data recvd %r" % packed)
                    retry_count = 5
                    if self.validate_peer:
                        x509 = self.tls.ssl.get_peer_cert()
                        if not self.validate_peer(x509):
                            continue
                    try:
                        self.socket_proc.send(packed)
                    except ValueError:
                        LOGC.error("Cannot decode message %s" % packed)
                    except Exception, ex:
                        LOGC.error("Error %r" % ex)

            except ConnectionException, connex:
                LOGC.error(connex)
                LOGC.warn("Rebuilding ssl connection")
                self.shutdown()
                raise
            except zmq.ZMQError, zerr:
                if zerr.errno == zmq.ETERM or zerr.errno == zmq.ENOTSUP \
                        or zerr.errno == zmq.ENOTSOCK:
                    # System interrupt
                    break
                LOGC.exception(zerr)
            except Exception, ex:
                raise

        self.poller.unregister(self.zmq_socket)
        self.poller.unregister(self.socket_proc)
        try:
            self.zmq_socket.send('-255')
        except:
            pass
        self.shutdown()
        if not retry_count:
            LOGC.warn("Could not establish connection to the remote server. "
                      "Check certificates and network connection")
        LOGC.debug("TLSZmqClient exited")

    def shutdown(self):
        LOGC.debug('Closing TLSZmqClient')
        self.stopped.set()
        self.tls.shutdown()
        self.zmq_socket.close()
        self.socket_proc.close()
        LOGC.debug('TLSZmqClient closed')


class _TLSZmq(object):

    _ctx = None

    def __init__(self, log, proto='sslv3', type='Server', identity=None,
                 cert=None, key=None, ca=None, verify_func=None,
                 cert_password=None):
        """
        Creates a TLS/SSL wrapper for handling handshaking and encryption
        of messages over insecure sockets

        Arguments:

        proto       --  Protocol of the wrapper.
                        Valid values are: 'sslv3' or 'tlsv1'.
                        Required.

        type        --  Type of the instance - 'Server' or 'Client'

        identity    --  unique id of the wrapper. Max length is 32 chars,
                        due to limitation in OpenSSL. Needed for proper
                        packet handling. Required.

        cert        --  Certificate file name. Used on both
                        client and server side.
                        Mandatory for the server. Optional for the client.
                        Usually the client uses a signed certificate from the
                        server's CA.

        key         --  File name with PEM-encoded key of the client/server.
                        Mandatory with cert.

        ca          --  CA certificate file name. Not applicable for clients,
                        Mandatory with server that checks issues client certs.

        verify_func  --  Verify locations. Certificate file(s) to use to verify
                        client certificates. Used for multi-node setup.

        cert_password --    Certificate private key password

        """
        self.DEPTH = 5
        self.BUF_LEN = 1024
        self.identity = identity
        self.LOG = log
        self.proto = proto
        assert self.proto in ('sslv3', 'tlsv1')
        self.cert = cert
        self.key = key
        assert (self.cert and self.key) or (not self.cert and not self.key)
        self.ca = ca
        self.verify_func = verify_func
        self.cert_password = cert_password
        assert (not self.ca) or (self.ca and self.cert and self.key)

        self.type = type
        if self.is_server:
            assert identity and len(self.identity) <= 32, identity
        self._init_ctx()
        self._init_ssl()

    @property
    def is_server(self):
        return self.type == 'Server'

    @property
    def is_client(self):
        return self.type == 'Client'

    def set_verify_callback(self, verify_cb):
        """
        Sets a vertificate verification callback.
        Pass a function of the type:
            `def callback(X509cert, verify_depth, intermediate_status):`

        Where:
            X509Cert        --  a M2Crypto.X509.X509 object
            verify_depth    --  The depth of verification tree
            intermediate_status --  The status calculated so far.
                                    You can override this.
        """
        self.verify_cb = verify_cb

    def _verify_callback(self, ctx, _x509, errnum, depth, ok):
        try:
            x509 = m.X509.X509(_x509)
        except Exception:
            return False
        if hasattr(self, 'verify_cb'):
            ok = self.verify_cb(x509, depth, ok)
            del x509
        return ok

    def _pass_callback(self, *args):
        return self.cert_password

    def _init_ctx(self):

        if _TLSZmq._ctx is None:
            self.LOG.debug('Creating SSL Context')
            # Init singleton SSL.Context
            _TLSZmq._ctx = m.SSL.Context(self.proto)

            if self.cert:
                try:
                    _TLSZmq._ctx.load_cert(self.cert, keyfile=self.key,
                                           callback=self._pass_callback)
                except m.SSL.SSLError, ex:
                    self.LOG.exception(ex)
                    self.LOG.error("Cannot load certificates:\n%s\n%s" %
                                   (self.cert, self.key))
        self.ctx = _TLSZmq._ctx

        self.ctx.set_options(m.SSL.op_no_sslv2)
        if self.is_server and (self.ca or self.verify_func):
            verify_flags = m.SSL.verify_peer
            self.ctx.set_verify(
                verify_flags, self.DEPTH, self._verify_callback)
            if callable(self.verify_func):
                self.ctx.set_allow_unknown_ca(True)
                self.verify_cb = self.verify_func
            elif self.verify_func:
                self.ctx.set_client_CA_list_from_file(self.ca)
                if isinstance(self.verify_func, basestring):
                    self.LOG.debug("Loading verification CA from %s" %
                                   self.verify_func)
                    self.ctx.load_verify_locations(self.verify_func)
                elif isinstance(self.verify_func, list):
                    for loc in self.verify_func:
                        self.LOG.debug("Loading verification CA from %s" % loc)
                        self.ctx.load_verify_locations(loc)
        elif self.is_client:
            if self.ca:
                verify_flags = m.SSL.verify_client_once
                self.ctx.set_allow_unknown_ca(0)
                self.ctx.load_verify_locations(self.ca)
                self.ctx.set_verify(
                    verify_flags, self.DEPTH, self._verify_callback)
            elif self.cert:
                if not hasattr(_TLSZmq, '_ca_warn'):
                    self.LOG.warn("Client certificate is used, but no CA cert "
                                  "is passed. The server will not be "
                                  "verified upon request")
                    _TLSZmq._ca_warn = 1  # show only once

    def _init_ssl(self):
        self.rbio = m.BIO.MemoryBuffer()
        self.wbio = m.BIO.MemoryBuffer()

        self.ssl = m.SSL.Connection(self.ctx, sock=None)
        self.ssl.set_bio(self.rbio, self.wbio)

        self.app_to_ssl = StringIO()
        self.ssl_to_zmq = StringIO()
        self.zmq_to_ssl = StringIO()
        self.ssl_to_app = StringIO()

        if self.is_server:
            if self.ca:
                self.ssl.set_client_CA_list_from_context()
            self.ctx.set_session_id_ctx(self.identity)
            self.ssl.set_session_id_ctx(self.identity)
            self.ssl.set_accept_state()
        else:
            self.ssl.set_connect_state()

    def update(self):
        sent = False
        if self.zmq_to_ssl.len:
            wrc = self.rbio.write(self.flush(self.zmq_to_ssl))
            self.LOG.debug('%s written to BIO' % (wrc))
        if self.app_to_ssl.len:
            rc = self.ssl.write(self.app_to_ssl.getvalue())
            if not self.continue_ssl(rc):
                raise Exception('SSL Error')
            if rc == self.app_to_ssl.len:
                self.app_to_ssl.truncate(0)
                sent = True
            self.LOG.debug("%s written to SSL" % (rc))

        self.net_read()
        self.net_write()
        return sent

    def continue_ssl(self, rc):
        err = self.ssl.ssl_get_error(rc)
        if err in (2, 1):
            # 1: SSL Error, possible cert issue
            # 2: SSL_ERROR_WANT_READ
            return True
        if err:
            self.LOG.warn("SSL Error: [%s] %s" %
                          (err, (m.m2.err_reason_error_string(err))))
            return False
        return True

    def net_read(self):
        while True:
            try:
                rc = self.ssl.read(self.BUF_LEN)
            except m.SSL.SSLError, ex:
                # break
                if self.is_client:
                    raise ConnectionException(ex.message)
                self.LOG.warn("SSL ERROR: %s" % str(ex))
                break
            if rc is None:
                break
            self.ssl_to_app.write(rc)

    def net_write(self):
        while True:
            try:
                read = self.wbio.read()
            except (m.SSL.SSLError, m.BIO.BIOError), ex:
                self.LOG.exception(ex)
                continue
            if read is None:
                break
            self.ssl_to_zmq.write(read)
        if self.ssl_to_zmq.len:
            self.LOG.debug("%s read from BIO" % (self.ssl_to_zmq.len))

    def can_recv(self):
        return self.ssl_to_app.len

    def needs_write(self):
        return self.ssl_to_zmq.len

    def recv(self):
        return self.flush(self.ssl_to_app)

    def get_data(self):
        return self.flush(self.ssl_to_zmq)

    def put_data(self, data):
        self.zmq_to_ssl.write(data)

    def send(self, data):
        self.app_to_ssl.write(data)

    def flush(self, io):
        ret = io.getvalue()
        io.truncate(0)
        return ret

    def shutdown(self):
        self.ssl.set_ssl_close_flag(m.m2.bio_close)
        self.ssl.shutdown(
            m.SSL.SSL_RECEIVED_SHUTDOWN | m.SSL.SSL_SENT_SHUTDOWN)
        if hasattr(self, 'rbio'):
            self.rbio.close()
            self.wbio.close()
        self.ssl.close()
        if hasattr(self, 'rbio'):
            del self.rbio
            del self.wbio
        _TLSZmq._ctx = None


class TLSZmqServer(_TLSZmq):

    def __init__(self, identity, cert, key, ca=None, proto='sslv3',
                 verify_func=None, cert_password=None):
        """
        Creates a TLS/SSL wrapper for handling handshaking and encryption
        of messages over insecure sockets

        Arguments:

        proto       --  Protocol of the wrapper.
                        Valid values are: 'sslv3' or 'tlsv1'.
                        Required.

        identity    --  unique id of the wrapper. Max length is 32 chars,
                        due to limitation in OpenSSL. Needed for proper
                        packet handling. Required.

        cert        --  Certificate file name. Mandatory.

        key         --  File name with PEM-encoded key of the server.
                        Mandatory.

        ca          --  CA certificate file name. Not applicable for clients,
                        Mandatory with server that checks issues client certs.

        verify_func  --  Verify function. If a CA Certificate file(s) are
                         passed - use them toverify client certificates.
                         If a function is provided - use it to verify
                         the client certificate.

        cert_password --    Certificate private key password

        """
        super(TLSZmqServer, self).__init__(LOGS, proto, 'Server', identity,
                                           cert, key, ca,
                                           verify_func=verify_func,
                                           cert_password=cert_password)


class TLSZmqClient(_TLSZmq):

    def __init__(self, proto, cert, key, ca=None, cert_password=None):
        """
        Creates a TLS/SSL wrapper for handling handshaking and encryption
        of messages over insecure sockets

        Arguments:

        proto       --  Protocol of the wrapper.
                        Valid values are: 'sslv3' or 'tlsv1'.
                        Required.

        cert        --  Certificate file name.
                        Usually the client uses a signed certificate from the
                        server's CA.

        key         --  File name with PEM-encoded key of the client.
                        Mandatory with cert.

        ca          --  CA file for server verification

        cert_password --    Certificate private key password

        """
        super(TLSZmqClient, self).__init__(LOGC, type='Client',
                                           cert=cert, key=key, ca=ca,
                                           cert_password=cert_password)
