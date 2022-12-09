#!/usr/bin/env python


from bcc import BPF


b = BPF(text="""
struct DataOut {
    u32 a;
    u32 b;
};
BPF_PERF_OUTPUT(data_out);

BPF_HASH(flt, u32, struct DataOut);

TRACEPOINT_PROBE(syscalls, sys_enter_sync) {
    u32 tid = bpf_get_current_pid_tgid();

    struct DataOut data = { };
    data.a = bpf_get_prandom_u32() >> 24;
    data.b = 0x27;
    flt.insert(&tid, &data);

    struct DataOut *out = flt.lookup(&tid);
    if (out != NULL) {
        data.b = out->a;
        flt.update(&tid, &data);
    }

    data_out.perf_submit(args, &data, sizeof(struct DataOut));
    return 0;
}
""")


def printer(cpu, data, size):
    info = b["data_out"].event(data)
    print("{}\n{}\n".format(hex(info.a), hex(info.b)))


print("Started tracing. Press Ctrl+C to stop.")

b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
