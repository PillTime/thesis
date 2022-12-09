#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <linux/ieee80211.h>
#include <../net/mac80211/ieee80211_i.h>
#include <linux/skbuff.h>


struct DataOut {
    u8 mac[ETH_ALEN];
    char iface[IFNAMSIZ];
    u64 ts;
    u8 reason;
    u16 frm_ctrl;
    u16 seq_ctrl;
    u16 qos_ctrl;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    u8 addr4[ETH_ALEN];
};
BPF_PERF_OUTPUT(dataout);

BPF_HASH(pass, u32, struct DataOut);


int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    u64 ts = bpf_ktime_get_ns();
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    struct DataOut data = {};
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sdata->name);
    data.ts = ts;
    data.reason = 1;
    data.frm_ctrl = mac->frame_control;
    data.seq_ctrl = mac->seq_ctrl;
    bpf_probe_read_kernel(data.addr1, sizeof(u8) * ETH_ALEN, mac->addr1);
    bpf_probe_read_kernel(data.addr2, sizeof(u8) * ETH_ALEN, mac->addr2);
    bpf_probe_read_kernel(data.addr3, sizeof(u8) * ETH_ALEN, mac->addr3);

    u16 hasqos = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA;
    u16 checkqos = IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA;
    u16 check4addr = IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS;
    if ((mac->frame_control & check4addr) == check4addr) {
        bpf_probe_read_kernel(data.addr4, sizeof(u8) * ETH_ALEN, mac->addr4);
        if ((mac->frame_control & checkqos) == hasqos) {
            bpf_probe_read_kernel(&data.qos_ctrl, 2, mac + 30);
        }
    } else if ((mac->frame_control & checkqos) == hasqos) {
        bpf_probe_read_kernel(&data.qos_ctrl, 2, mac + 24);
    }
    // +30 & +24 come from `ieee80211_get_qos_ctl()` in the linux kernel

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.update(&tid, &data);
    return 0;
}


int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    u64 ts = bpf_ktime_get_ns();
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    struct DataOut data = {};
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sdata->name);
    data.ts = ts;
    data.reason = 2;
    data.frm_ctrl = mac->frame_control;
    data.seq_ctrl = mac->seq_ctrl;
    bpf_probe_read_kernel(data.addr1, sizeof(u8) * ETH_ALEN, mac->addr1);
    bpf_probe_read_kernel(data.addr2, sizeof(u8) * ETH_ALEN, mac->addr2);
    bpf_probe_read_kernel(data.addr3, sizeof(u8) * ETH_ALEN, mac->addr3);

    u16 hasqos = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA;
    u16 checkqos = IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA;
    u16 check4addr = IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS;
    if ((mac->frame_control & check4addr) == check4addr) {
        bpf_probe_read_kernel(data.addr4, sizeof(u8) * ETH_ALEN, mac->addr4);
        if ((mac->frame_control & checkqos) == hasqos) {
            bpf_probe_read_kernel(&data.qos_ctrl, 2, mac + 30);
        }
    } else if ((mac->frame_control & checkqos) == hasqos) {
        bpf_probe_read_kernel(&data.qos_ctrl, 2, mac + 24);
    }
    // +30 & +24 come from `ieee80211_get_qos_ctl()` in the linux kernel

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

    // take out of kernel space (ebpf map)
    struct DataOut out = {};
    bpf_probe_read_kernel(&out, sizeof(struct DataOut), data);

    dataout.perf_submit(ctx, &out, sizeof(struct DataOut));
    pass.delete(&tid);
    return 0;
}
