#!/usr/bin/env python

from bcc import BPF


BPF(text="""
int kprobe__sys_clone(void *ctx)
{
    bpf_trace_printk("Hello, world!\\n");
    return 0;
}
""").trace_print()
