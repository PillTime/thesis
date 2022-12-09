#!/usr/bin/env python


from bcc import BPF


b = BPF(text="""
#include <linux/skbuff.h>

struct Pair {
    u8 fn;
    struct sk_buff *skb;
};

BPF_HASH(flt, u32, struct Pair);

struct DataOut {
    u8 fn;
    void *skb;
};
BPF_PERF_OUTPUT(data_out);

int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, void *sdata, struct sk_buff *skb) {
    u32 tid = bpf_get_current_pid_tgid();
    struct Pair p = {};
    p.fn = 1;
    p.skb = skb;
    flt.insert(&tid, &p);
    return 0;
}

int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, void *sdata, struct sk_buff *skb) {
    u32 tid = bpf_get_current_pid_tgid();
    struct Pair p = {};
    p.fn = 2;
    p.skb = skb;
    flt.insert(&tid, &p);
    return 0;
}

int kprobe__mesh_path_add(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct Pair *p = flt.lookup(&tid);
    if (p == NULL) return 1;

    struct DataOut data = {};
    data.fn = p->fn;
    data.skb = p->skb;
    data_out.perf_submit(ctx, &data, sizeof(data));

    flt.delete(&tid);
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
