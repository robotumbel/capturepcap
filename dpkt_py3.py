#!/usr/bin/env python

import dpkt

f = open('pcap.pcap','rb')
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    try:
        print(repr(tcp))
    except:
        print(repr(tcp))

f.close()