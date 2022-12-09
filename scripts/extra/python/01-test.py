#!/usr/bin/env python

import scapy.all as scp
import time

t = scp.AsyncSniffer(iface="lo")
t.start()
time.sleep(3)
t.stop()

#from bcc import BPF
#
#def eventmanager(cpu, data, size):
#    print("wow")
#
#b = BPF(src_file="tracer.bpf.c")
#b["dataout"].open_perf_buffer(eventmanager)
#try:
#    while True:
#        b.perf_buffer_poll()
#except KeyboardInterrupt:
#    pass
