#!/usr/bin/env python

import scapy.all as scp


pcap = scp.rdpcap("outscapy.pcap")

for cap in pcap:
    if scp.Dot11 in cap:
        if cap.SC is not None:
            print("SC: ", hex(cap.SC))
        else:
            print("SC: n/a")
        print(cap.FCfield)
