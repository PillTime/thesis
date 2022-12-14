#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF


b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx)
{
    u64 ts, *tsp, delta, key = 0;

    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
    }

    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")

print("Tracing for quick sync's... Ctrl+C to end.")


start = 0
while True:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    if start == 0:
        start = ts
    ts -= start
    print("At time %.2fs: multiple sync's detected, last %sms ago." % (ts, ms))
