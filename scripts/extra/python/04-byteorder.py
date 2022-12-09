#!/usr/bin/env python

from bcc import BPF
import scapy.all as scp

# the code like this (no bitwise manipulation), it can be seen that wireshark
# switches the byte order, so what is passed through the kernel is in network
# (bigendian) order, while wireshark is in host (littleendian) order.
#
# ONLY IN FRAME_CONTROL
# IN SEQUENCE_CONTROL, WIRESHARK SHOWS THE NETWORK ORDER

b = BPF(text='''
#include <../net/mac80211/ieee80211_i.h>
#include <linux/ieee80211.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if.h>


struct DataOut {
    u16 frm_ctrl;
    u16 seq_ctrl;
    u16 from_ds;
    u16 to_ds;
    u16 seq_num;
    u16 frag_num;
    char name[IFNAMSIZ];
};
BPF_PERF_OUTPUT(dataout);

BPF_HASH(pass, u32, struct DataOut);


int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    struct DataOut data = { };
    data.frm_ctrl = mac->frame_control;
    data.seq_ctrl = mac->seq_ctrl;
    data.from_ds = (mac->frame_control & IEEE80211_FCTL_FROMDS) >> 9;
    data.to_ds = (mac->frame_control & IEEE80211_FCTL_TODS) >> 8;
    data.seq_num = (mac->seq_ctrl & IEEE80211_SCTL_SEQ) >> 4;
    data.frag_num = mac->seq_ctrl & IEEE80211_SCTL_FRAG;
    bpf_probe_read_kernel(data.name, sizeof(char) * IFNAMSIZ, sdata->name);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.update(&tid, &data);
    return 0;
}


int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    struct DataOut data = { };
    data.frm_ctrl = mac->frame_control;
    data.seq_ctrl = mac->seq_ctrl;
    data.from_ds = (mac->frame_control & IEEE80211_FCTL_FROMDS) >> 9;
    data.to_ds = (mac->frame_control & IEEE80211_FCTL_TODS) >> 8;
    data.seq_num = (mac->seq_ctrl & IEEE80211_SCTL_SEQ) >> 4;
    data.frag_num = mac->seq_ctrl & IEEE80211_SCTL_FRAG;
    bpf_probe_read_kernel(data.name, sizeof(char) * IFNAMSIZ, sdata->name);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.update(&tid, &data);
    return 0;
}


int kprobe__mesh_path_add(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct DataOut *data = pass.lookup(&tid);
    if (data == NULL) {
        return 1;
    }

    bpf_probe_read_kernel(data, sizeof(struct DataOut), data);
    dataout.perf_submit(ctx, data, sizeof(struct DataOut));

    pass.delete(&tid);
    return 0;
}

''')

def printer(cpu, data, size):
    info = b["dataout"].event(data)

    print("name: {}".format(str(info.name)))
    print("fc: 0x{:04x}".format(info.frm_ctrl))
    print("sc: 0x{:04x}".format(info.seq_ctrl))
    print("from: {} (0x{:01x})".format(info.from_ds, info.from_ds))
    print("to:   {} (0x{:01x})".format(info.to_ds, info.to_ds))
    print("seq:  {} (0x{:04x})".format(info.seq_num, info.seq_num))
    print("frg:  {} (0x{:02x})".format(info.frag_num, info.frag_num))
    print()


b["dataout"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        b["pass"].clear()
        exit()
