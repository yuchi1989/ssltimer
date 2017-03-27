#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function

from scapy.layers.ssl_tls import *
from scapy.layers.ssl_tls_crypto import *
import scapy.layers.ssl_tls as tls
import time

tls_version = TLSVersion.TLS_1_2
#ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]
#ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA384]
ciphers = [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA]
# ciphers = [TLSCipherSuite.RSA_WITH_RC4_128_SHA]
# ciphers = [TLSCipherSuite.DHE_RSA_WITH_AES_128_CBC_SHA]
# ciphers = [TLSCipherSuite.DHE_DSS_WITH_AES_128_CBC_SHA]
extensions = [TLSExtension() / TLSExtECPointsFormat(),
              TLSExtension() / TLSExtSupportedGroups()]

def verify_data_1(tls_ctx, data=None):

    if tls_ctx.negotiated.version >= tls.TLSVersion.TLS_1_3:
        if tls_ctx.client:
            prf_verify_data = tls_ctx.derive_client_finished()
        else:
            prf_verify_data = tls_ctx.derive_server_finished()
    else:
        if tls_ctx.client:
            label = TLSPRF.TLS_MD_CLIENT_FINISH_CONST
        else:
            label = TLSPRF.TLS_MD_SERVER_FINISH_CONST
        if data is None:
            verify_data = []
            for handshake in tls_ctx._walk_handshake_msgs():
                if handshake.haslayer(tls.TLSFinished):
                    # Special case of encrypted handshake. Remove crypto material to compute verify_data
                    verify_data.append("%s%s%s" % (chr(handshake.type), struct.pack(">I", handshake.length)[1:],
                                                   handshake[tls.TLSFinished].data))
                else:
                    verify_data.append(str(handshake))
        else:
            verify_data = [data]

    if tls_ctx.negotiated.version == tls.TLSVersion.TLS_1_2:
        prf_verify_data = tls_ctx.prf.get_bytes(tls_ctx.master_secret, label,
                                             tls_ctx.prf.digest.new("abc".join(verify_data)).digest(),
                                             num_bytes=12)
    else:
        prf_verify_data = tls_ctx.prf.get_bytes(tls_ctx.master_secret, label,
                                             "%s%s" % (MD5.new("".join(verify_data)).digest(),
                                                       SHA.new("".join(verify_data)).digest()),
                                             num_bytes=12)
    return prf_verify_data

def tls_do_round_trip_1(tls_socket, pkt, recv=True):
    resp = TLS()
    try:
        tls_socket.sendall(pkt)
        start_time = time.time()
        if recv:
            resp = tls_socket.recvall()
            if resp.haslayer(TLSAlert):
                alert = resp[TLSAlert]
                if alert.level != TLSAlertLevel.WARNING:
                    level = TLS_ALERT_LEVELS.get(alert.level, "unknown")
                    description = TLS_ALERT_DESCRIPTIONS.get(alert.description, "unknown description")
                    print("--- %s seconds ---" % (time.time() - start_time))
                    raise TLSProtocolError("%s alert returned by server: %s" % (level.upper(), description.upper()), pkt, resp)
    except socket.error as se:
        raise TLSProtocolError(se, pkt, resp)
    return resp

def tls_handshake_1(tls_socket, version, ciphers, extensions=[]):
    if version <= TLSVersion.TLS_1_2:
        client_hello = TLSRecord(version=version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSClientHello(version=version,
                                                                cipher_suites=ciphers,
                                                                extensions=extensions)])
        resp1 = tls_do_round_trip(tls_socket, client_hello)

        client_key_exchange = TLSRecord(version=version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        tls_socket.tls_ctx.get_client_kex_data()])
        client_ccs = TLSRecord(version=version) / TLSChangeCipherSpec()
        tls_do_round_trip(tls_socket, TLS.from_records([client_key_exchange, client_ccs]), False)
        
        #resp2 = tls_do_round_trip(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        #TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        resp2 = tls_do_round_trip_1(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        TLSFinished(data=verify_data_1(tls_socket.tls_ctx))]))
        #resp2 = tls_do_round_trip(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        #TLSFinished(data="abc")]))
        
        return resp1, resp2



def tls_timer(ip):
    with TLSSocket(client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
            print("Connected to server: %s" % (ip,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            try:
                server_hello, server_kex = tls_handshake_1(tls_socket, tls_version, ciphers, extensions)
                server_hello.show()
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            except NotImplementedError as nie:
                print("NotImplementedError: %s" % nie, file=sys.stderr) 
            else:
                resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: www.google.com\r\n\r\n"))
                print("Got response from server")
                resp.show()
            finally:
                #print(tls_socket.tls_ctx)
                pass


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("172.217.7.142", 443)
    tls_timer(server)