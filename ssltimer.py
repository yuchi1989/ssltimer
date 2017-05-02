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
import matplotlib as mpl
import matplotlib.pyplot as plt
import pickle

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

def save_object(obj, filename):
    with open(filename, 'wb') as output:
        pickle.dump(obj, output, pickle.HIGHEST_PROTOCOL)

def load_object(filename):
    with open(filename, 'rb') as input:
        return pickle.load(input)

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
                                             tls_ctx.prf.digest.new("aaa".join(verify_data)).digest(),
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
        if start_time == 0:
            start_time = time.time()
        if recv:
            if start_time != 0 and time_diff == 0:
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
        #hexdump(tls_socket.tls_ctx.premaster_secret)
        resp1 = tls_do_round_trip(tls_socket, client_hello)
        #if premaster_key != None:
            #tls_socket.tls_ctx.premaster_secret = premaster_key
        #tls_socket.tls_ctx.premaster_secret = "%s%s" % (struct.pack("!H", client_hello.version), 'a'*46)
        #hexdump(tls_socket.tls_ctx.premaster_secret)
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
                #server_hello.show()
            except TLSProtocolError as tpe:
                
                #tpe.response.show()
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                if time_diff != 0:
                    return time_diff
                elif start_time != 0:
                    time_diff = time.time() - start_time
                    print("---- %s seconds ----" % (time_diff))                
                return time_diff

            except NotImplementedError as nie:
                print("NotImplementedError: %s" % nie, file=sys.stderr)
                return 0
            else:
                #pass
                #resp = tls_socket.do_round_trip(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: www.google.com\r\n\r\n"))
                #print("Got response from server")
                #resp.show()
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

def scale(x_np):
    np_minmax = (x_np - x_np.min()) / (x_np.max() - x_np.min())
    return np_minmax



def reject_outliers(data, m=4):
    return data[abs(data - numpy.mean(data)) < m * numpy.std(data)]

def test_distribution_with_same_input(server):
    key = "\x03\x03" * 24
    time_list = []
    for k in range(100):
        try:
            dtime = tls_timer(server,key) 
        except:
            pass
        finally:
            if dtime != 0:
                time_list.append(dtime)    
    x = numpy.array(time_list)
    x = reject_outliers(x)
    n, bins, patches = plt.hist(x, 50, normed=1, facecolor='green', alpha=0.75)
    plt.show()

def comp_distribution_with_same_input(server1, server2):
    #key = "\x03\x03" * 24
    key = "\x11\x11" * 24
    time_list = []
    for k in range(100):
        try:
            while (dtime == 0):
                dtime = tls_timer(server1,key) 
        except:
            pass
        finally:
            if dtime != 0:
                time_list.append(dtime)
    x1 = numpy.array(time_list)
    save_object(x1,"data1.obj")
    x1 = reject_outliers(x1)

    #key = "\x03\x03" * 24
    key = "\x11\x11" * 24
    time_list = []
    for k in range(100):
        try:
            while (dtime == 0):
                dtime = tls_timer(server2,key)
        except:
            pass
        finally:
            time_list.append(dtime)
    x2 = numpy.array(time_list)
    save_object(x2,"data2.obj")
    x2 = reject_outliers(x2)
    
    f, (ax1, ax2) = plt.subplots(1, 2, sharey=True)
    ax1.hist(x1, 50, normed=1, facecolor='green', alpha=0.75)
    ax2.hist(x2, 50, normed=1, facecolor='green', alpha=0.75)
    plt.show()

def collect_data_with_same_input(server1, server2):
    #key = "\x03\x03" * 24
    key = "\x11\x11" * 24
    dtime = 0
    #blind
    
    for sample in range(50):
        time_list = []
        for k in range(100):
            try:
                while (dtime == 0):
                    dtime = tls_timer(server1,key) 
            except:
                pass
            finally:
                time_list.append(dtime)
                print(dtime)
                dtime = 0
        with open('sampledata3.csv', 'a') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(map(str,time_list) + ["0"])
    
    #vul
    dtime = 0
    for sample in range(50): 
        time_list = []   
        for k in range(100):
            try:
                while (dtime == 0 or dtime == None):
                    dtime = tls_timer(server2,key)
            except:
                pass
            finally:
                time_list.append(dtime)
                print(dtime)
                dtime = 0
        with open('sampledata3.csv', 'a') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(map(str,time_list) + ["1"])
def test(server1, server):
    key = "\x11\x11" * 24
    dtime = tls_timer(server1,key)
    print(dtime)
    dtime = tls_timer(server2,key)
    print(dtime)

def test1(server):
    dtime = 0
    key = "\x11\x11" * 24
    try:
        while (dtime == 0 or dtime == None):
            dtime = tls_timer(server,key)            
    except:
        pass
    finally:
        print(dtime)
        dtime = 0
    key = "\x03\x01" * 24
    try:
        while (dtime == 0 or dtime == None):
            dtime = tls_timer(server,key)            
    except:
        pass
    finally:
        print(dtime)
        dtime = 0

def test_variance_with_diff_input(server):
    pmsdata = range(16)
    timingdata = []
    data_to_plot = []
    pms = "\xd0"
    dtime = 0
    for i in range(16):
        hexdump(pms)            
        key = "\x00\x00"+"\x00"*14 + pms + "\x00" * 31
        time_list = []
        for k in range(10):
            try:
                while (dtime == 0 or dtime == None):
                    dtime = tls_timer(server,key)            
            except:
                pass
            finally:
                time_list.append(dtime)
                print(dtime)
                dtime = 0
                #print(time_list)
        timingdata.append(numpy.median(numpy.array(time_list)))
        data_to_plot.append(numpy.array(time_list))
        if i != 15:
            pms = splus(pms, "\x01")
    
    print(numpy.var(scale(numpy.array(timingdata))))
    print ("-------------------------")
    variance = []
    for d in data_to_plot:
        variance.append(numpy.var(d))
        print (numpy.var(d))
    print ("-------------------------")
    print(numpy.mean(numpy.array(variance)))

    #with open('timingdata.csv', 'wb') as csvfile:
        #writer = csv.writer(csvfile)
        #for i in pmsdata:
            #writer.writerow([str(pmsdata[i])] + [str(timingdata[i])])
    mpl_fig = plt.figure()
    ax = mpl_fig.add_subplot(111)    
    ax.set_ylim([0.0025,0.0035])

    ax.boxplot(data_to_plot, showfliers=False)
    plt.show()

def test_diff_input(server):
    x = numpy.array(range(8))
    y = []
    timingdata = []
    data_to_plot = []
    pms = "\x00"
    dtime = 0
    for i in range(8):
        hexdump(pms)            
        key = pms + "\x00" * 63
        time_list = []
        for k in range(50):
            try:
                while (dtime == 0 or dtime == None):
                    dtime = tls_timer(server,key)
            except:
                pass
            finally:
                time_list.append(dtime)
                print(dtime)
                dtime = 0
                #print(time_list)
        y.append(numpy.mean(numpy.array(time_list)))
        timingdata.append(numpy.median(numpy.array(time_list)))
        data_to_plot.append(numpy.array(time_list))
        if i != 7:
            pms = splus(pms, "\x20")
    
    print(numpy.var(scale(numpy.array(timingdata))))
    print ("-------------------------")
    variance = []
    for d in data_to_plot:
        variance.append(numpy.var(d))
        print (numpy.var(d))
    print ("-------------------------")
    print(numpy.mean(numpy.array(variance)))

    #with open('timingdata.csv', 'wb') as csvfile:
        #writer = csv.writer(csvfile)
        #for i in pmsdata:
            #writer.writerow([str(pmsdata[i])] + [str(timingdata[i])])
    """
    mpl_fig = plt.figure()
    ax = mpl_fig.add_subplot(111)    
    ax.set_ylim([0.0025,0.0035])

    ax.boxplot(data_to_plot, showfliers=False)
    """
    plt.plot(x,y)
    plt.show()

def find_peak(v):
    i = 0
    r = []
    while i+1 < len(v):
        r.append(0)
        if i == 0 and v[i] > v[i+1]:
            r[0] = 1
            i = i + 1
            continue
        if v[i-1] < v[i] and v[i] > v[i+1]:
            r[i] = 1
        i = i + 1
    if v[i-1] < v[i]:
        r.append(1)
    else:
        r.append(0)
    return r

def progression(v):
    i = 0
    r = []
    while i+1 < len(v):
        r.append(v[i+1]-v[i])
        i = i + 1
    return r

def display(server):
    f1 = []
    f2 = []
    f3 = []
    m1 = []
    m2 = []
    x = numpy.array(range(4))
    y = []
    timingdata = []
    data_to_plot = []
    pms = "\x00"
    dtime = 0
    for i in range(4):
        hexdump(pms)
        key = pms + "\x00" * 63
        time_list = []
        for k in range(80):
            try:
                while (dtime == 0 or dtime == None):
                    dtime = tls_timer(server,key)
            except:
                pass
            finally:
                time_list.append(dtime)
                print(dtime)
                dtime = 0
                #print(time_list)
        y.append(numpy.mean(numpy.array(time_list)))

        if i != 3:
            pms = splus(pms, "\x40")
    
    f1 = find_peak(y)
    f2 = progression(y)
    plt.plot(x,y,'-or')
    ticks = ["00", "01", "10", "11"]
    plt.xticks(x, ticks)
    plt.show()

def analyze(server):
    f1 = []
    f2 = []
    f3 = []
    m1 = []
    m2 = []
    for c in range(2):
        x = numpy.array(range(4))
        y = []
        timingdata = []
        data_to_plot = []
        pms = "\x00"
        dtime = 0
        for i in range(4):
            hexdump(pms)
            key = pms + "\x00" * 63
            time_list = []
            for k in range(80):
                try:
                    while (dtime == 0 or dtime == None):
                        dtime = tls_timer(server,key)
                except:
                    pass
                finally:
                    time_list.append(dtime)
                    print(dtime)
                    dtime = 0
                    #print(time_list)
            y.append(numpy.mean(numpy.array(time_list)))

            if i != 3:
                pms = splus(pms, "\x40")
        
        f1 = find_peak(y)
        f2 = progression(y)
        m1.append(f1)
        m2.append(f2)
    print("var(m1):")
    print (m1)
    print (numpy.var(m1,0))
    print(numpy.mean(numpy.var(m1,0)))
    print("var(m2):")
    print (numpy.var(m2,0))
    print(numpy.mean(numpy.var(m2,0)))
    return m1, numpy.var(m1,0), numpy.mean(numpy.var(m1,0))
    #plt.plot(x,y,'-or')
    #plt.show()
def evaluate(server1,server2):
    f = open("result.txt","w")
    for i in range(20):
        m, v, mv = analyze(server1)
        f.write(str(server1))
        f.write(str(m))
        f.write(str(v))
        f.write(str(mv))
        f.write("\n")
        m, v, mv = analyze(server2)
        f.write(str(server2))
        f.write(str(m))
        f.write(str(v))
        f.write(str(mv))
        f.write("\n")
    f.close()
if __name__ == "__main__":
    if len(sys.argv) == 3:
        server = (sys.argv[1], int(sys.argv[2]))
        #analyze(server)
        #display(server)
    if len(sys.argv) == 5:
        server1 = (sys.argv[1], int(sys.argv[2]))
        server2 = (sys.argv[3], int(sys.argv[4]))
        evaluate(server1,server2)