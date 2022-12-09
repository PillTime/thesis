#!/usr/bin/env python


from bcc import BPF


b = BPF(text="""
#include <linux/skbuff.h>

struct DataOut {
    u8 fn;
    void *skb;
};
BPF_PERF_OUTPUT(data_out);

int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, void *sdata, void *skb) {
    struct DataOut data = { };
    data.fn = 1;
    data.skb = skb;
    data_out.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, void *sdata, void *skb) {
    struct DataOut data = { };
    data.fn = 2;
    data.skb = skb;
    data_out.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
""")


def printer(cpu, data, size):
    info = b["data_out"].event(data)

    if info.fn == 1:
        print("mesh_nexthop_resolve")
    elif info.fn == 2:
        print("ieee80211_mesh_rx_queued_mgmt")

    print(hex(info.skb))
    print()


print("Started tracing. Press Ctrl+C to stop.")

b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
