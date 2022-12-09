#!/usr/bin/env python

from __future__ import print_function
from bcc import BPF


b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

BPF_PERF_OUTPUT(out);
struct data_t {
    u64 ts, ms;
};

int do_trace(struct pt_regs *ctx)
{
    struct data_t data = {};
    u64 ts, *tsp, delta, key = 0;

    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            data.ts = bpf_ktime_get_ns() / 1000000;
            data.ms = delta / 1000000;
            out.perf_submit(ctx, &data, sizeof(data));
        }
    }

    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")


start = 0
def printer(cpu, data, size):
    global start
    out = b["out"].event(data)
    if start == 0:
        start = out.ts
    ts = (out.ts - start) / 1000
    ms = out.ms
    print("At time %.2fs: multiple sync's detected, last %sms ago." % (ts, ms))

b["out"].open_perf_buffer(printer)

print("Tracing for quick sync's... Ctrl+C to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
