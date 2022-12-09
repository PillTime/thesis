#!/usr/bin/env python


from bcc import BPF


b = BPF(text="""
struct DataOut {
    u64 a;
    u64 b;
};
BPF_PERF_OUTPUT(data_out);

TRACEPOINT_PROBE(syscalls, sys_enter_sync) {
    struct DataOut data = { };
    data.a = bpf_ktime_get_ns();
    data.b = 27;
    data_out.perf_submit(args, &data, sizeof(data));

    data.b = data.a;
    data_out.perf_submit(args, &data, sizeof(data));

    return 0;
}
""")


def printer(cpu, data, size):
    info = b["data_out"].event(data)
    print("{}\n{}\n".format(info.a, info.b))


print("Started tracing. Press Ctrl+C to stop.")

b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
