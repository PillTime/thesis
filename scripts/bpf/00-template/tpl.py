#!/usr/bin/env python

from bcc import BPF


b = BPF(src_file="tpl.bpf.c")


def printer(cpu, data, size):
    print()


print("Started tracing. Press Ctrl+C to stop.\n")

b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
