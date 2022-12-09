#!/usr/bin/python3

from bcc import BPF
import sys
import time

bpf = BPF(text='''
// como vejo q é ieee80211_hdr e nao por exemplo ethernet_t ?

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>
#include <../net/mac80211/ieee80211_i.h>

BPF_HASH(pass, u64, u16);
BPF_HASH(helper, u64, u8);

int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    u8 magic = 27;
    u64 id = (u64)skb;
    helper.insert(&id, &magic);
    return 0;
}

int pkt_mon(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    u16 data = 0;
    u64 skbid = (u64)skb;

    u8 *inmap = helper.lookup(&skbid);
    if (inmap == NULL) {
        struct ieee80211_hdr *mac = cursor_advance(cursor, sizeof(*mac));
        data = mac->frame_control;
        helper.delete(&skbid);
    }

    pass.update(&skbid, &data);
    return -1;
}
''')

BPF.attach_raw_socket(bpf.load_func("pkt_mon", BPF.SOCKET_FILTER), "{}".format(sys.argv[1]))
out = bpf.get_table("pass")

try:
    while True:
        for k, v in sorted(out.items(), key=lambda out: out[1].value):
            print(v.value, hex(k.value))
        bpf["pass"].clear()
        time.sleep(1)
except KeyboardInterrupt:
    for k, v in sorted(out.items(), key=lambda out: out[1].value):
        print(v.value, hex(k.value))
    bpf["pass"].clear()
    sys.exit()
