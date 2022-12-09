#!/usr/bin/env python

from bcc import BPF


b = BPF(text="""
#include <linux/skbuff.h>

struct DataOut {
    u8 fn;
    void *skb;
};
BPF_PERF_OUTPUT(data_out);

BPF_HASH(pass, u32, struct DataOut);

int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, void *sdata, void *skb)
{
    struct DataOut data = { };
    data.fn = 1;
    data.skb = skb;

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.update(&tid, &data);
    return 0;
}

int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, void *sdata, void *skb)
{
    struct DataOut data = { };
    data.fn = 2;
    data.skb = skb;

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.update(&tid, &data);
    return 0;
}

int kprobe__mesh_path_add(struct pt_regs *ctx, void *sdata)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct DataOut *data = pass.lookup(&tid);
    if (data == NULL) {
        return 1;
    }

    struct DataOut out = { };
    bpf_probe_read_kernel(&out, sizeof(struct DataOut), data);

    data_out.perf_submit(ctx, &out, sizeof(struct DataOut));
    pass.delete(&tid);
    return 0;
}
""")


def printer(cpu, data, size):
    info = b["data_out"].event(data)

    global counter
    counter += 1
    if info.fn == 1:
        print("---{:02}--- mesh_nexthop_resolve --------".format(counter))
    elif info.fn == 2:
        print("---{:02}--- ieee80211_mesh_rx_queued_mgmt --------".format(counter))
    else:
        print("---{:02}--- UNKNOWN REASON --------\n".format(counter))
        return

    print("{:#018x}\n".format(info.skb))


print("Started tracing. Press Ctrl+C to stop.")

counter = 0
b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        b["pass"].clear()
        exit()
