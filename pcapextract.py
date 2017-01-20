import sys
import dpkt
from printer import *


def parse_pcap_file(filename, data_callback, req_ip):
    splitfiles = False
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    if splitfiles:
        sout = sys.stdout
        iii = 0

    if req_ip is not None:
        req_ip = ''.join(chr(int(c)) for c in req_ip.split('.'))

    conn = dict()
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if type(ip) == str:
            continue

        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        if req_ip is not None and ip.src != req_ip and ip.dst != req_ip:
            continue

        tcp = ip.data

        tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)

        if tupl in conn:
            conn[tupl] = conn[tupl] + tcp.data
        else:
            conn[tupl] = tcp.data

        srcip = '.'.join(str(ord(c)) for c in ip.src) + ':' + str(tcp.sport)
        dstip = '.'.join(str(ord(c)) for c in ip.dst) + ':' + str(tcp.dport)

        try:
            stream = conn[tupl]

            if stream[:4] == 'HTTP':
                http = dpkt.http.Response(stream)
            else:
                http = dpkt.http.Request(stream)

            if splitfiles:
                sys.stdout = open('queries/' + str(iii) + '.txt', 'wb')
                iii += 1

            if http.body:
                pprint('\n\n')
                if isinstance(http, dpkt.http.Response):
                    pprint('HTTP', '<<<', http.status, ',', len(http.body), 'bytes', dstip, '<<<', srcip)
                else:
                    host = ''
                    if 'host' in http.headers:
                        host = http.headers['host']
                    pprint('HTTP', http.method, http.uri, ',', len(http.body), 'bytes', host, srcip, '>>>', dstip)

                indent()
                try:
                    data_callback(http.body, isinstance(http, dpkt.http.Response))
                except Exception as e:
                    pprint('ERROR', str(e), repr(e))
                zero_indent()

            if splitfiles:
                sys.stdout.close()

            stream = stream[len(http):]
            if len(stream) == 0:
                del conn[tupl]
            else:
                conn[tupl] = stream
        except dpkt.UnpackError as e:
            pass

    if splitfiles:
        sys.stdout = sout
    f.close()
