#!/usr/bin/env python


from bcc import BPF


b = BPF(text="""
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
#include <../net/mac80211/ieee80211_i.h>

struct DataOut {
    u8 fn;
    void *skb1;
    void *skb2;
    u8 val1;
    u8 val2;
};
BPF_PERF_OUTPUT(data_out);

BPF_HASH(flt, u32, struct DataOut);

/*int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, void *sdata, struct sk_buff *skb) {
    u32 tid = bpf_get_current_pid_tgid();

    struct DataOut data = { };
    data.fn = 1;
    data.skb1 = skb;          // `skb` é um pointer
    data.skb2 = (void *)0x27;
    data.val1 = bpf_get_prandom_u32() >> 24;
    data.val2 = 0x27;
    flt.insert(&tid, &data);  // `flt` é um hash map com funçoes de insert, delete, etc

    struct DataOut *out = flt.lookup(&tid);
    if (out != NULL) {
        out->skb2 = out->skb1;
        out->val2 = out->val1;
        flt.update(&tid, out);
    }

    data_out.perf_submit(ctx, &data, sizeof(struct DataOut));
    return 0;
}*/

int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb) {
    u32 tid = bpf_get_current_pid_tgid();

    u8 addr[6];
    bpf_probe_read_kernel(addr, 6, sdata->vif.addr);

    if (addr[5] != 1) {
        return 1;
    }

    struct DataOut data = { };
    data.fn = 2;
    data.skb1 = skb;
    data.skb2 = (void *)0x27;
    data.val1 = bpf_get_prandom_u32() >> 24;
    data.val2 = 0x27;
    flt.insert(&tid, &data);

    struct DataOut *out = flt.lookup(&tid);
    if (out != NULL) {
        data.skb2 = out->skb1;

        ///// ESTES DOIS /////
        data.val2 = out->val1;                                       // DA MAL
        bpf_probe_read_kernel(&data.val2, sizeof(u8), &data.val1); // DA BEM

        //flt.update(&tid, &data);
    }

    //struct DataOut data2 = { };
    //bpf_probe_read_kernel(&(data2.val1), sizeof(u8), &(out->val1));
    //bpf_probe_read_kernel(&(data2.val2), sizeof(u8), &(out->val2));
    //data2.val2 = out->val2;
    data_out.perf_submit(ctx, &data, sizeof(struct DataOut));
    return 0;
}
""")


def printer(cpu, data, size):
    info = b["data_out"].event(data)
    if info.fn == 1:
        print("mesh_nexthop_resolve")
    elif info.fn == 2:
        print("ieee80211_mesh_rx_queued_mgmt")
    print("{}\n{}\n".format(hex(info.val1), hex(info.val2)))


print("Started tracing. Press Ctrl+C to stop.")

b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
