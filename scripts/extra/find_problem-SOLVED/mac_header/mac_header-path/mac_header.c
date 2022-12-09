#include <../net/mac80211/ieee80211_i.h>
#include <linux/ieee80211.h>
#include <linux/skbuff.h>
#include <uapi/linux/if_ether.h>


struct DataOut {
    u8 fn;
    u16 seq_num;
    u16 frm_num;
    u8 ds_from;
    u8 ds_to;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    u8 addr4[ETH_ALEN];
    u8 mac[ETH_ALEN];
    void *skb;
};
BPF_PERF_OUTPUT(data_out);

BPF_HASH(pass, u32, struct DataOut);


int kprobe__mesh_nexthop_resolve(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    struct DataOut data = {};
    data.fn = 1;
    data.seq_num = mac->seq_ctrl >> 4;
    data.frm_num = mac->seq_ctrl & 0xf;
    data.ds_from = mac->frame_control >> 8 & 0x2;
    data.ds_to = mac->frame_control >> 8 & 0x1;
    bpf_probe_read_kernel(data.addr1, sizeof(u8) * ETH_ALEN, mac->addr1);
    bpf_probe_read_kernel(data.addr2, sizeof(u8) * ETH_ALEN, mac->addr2);
    bpf_probe_read_kernel(data.addr3, sizeof(u8) * ETH_ALEN, mac->addr3);
    bpf_probe_read_kernel(data.addr4, sizeof(u8) * ETH_ALEN, mac->addr4);
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    data.skb = skb;

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.insert(&tid, &data);
    return 0;
}

int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, struct sk_buff *skb)
{
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    struct DataOut data = {};
    data.fn = 2;
    data.seq_num = mac->seq_ctrl >> 4;
    data.frm_num = mac->seq_ctrl & 0xf;
    data.ds_from = mac->frame_control >> 8 & 0x2;
    data.ds_to = mac->frame_control >> 8 & 0x1;
    bpf_probe_read_kernel(data.addr1, sizeof(u8) * ETH_ALEN, mac->addr1);
    bpf_probe_read_kernel(data.addr2, sizeof(u8) * ETH_ALEN, mac->addr2);
    bpf_probe_read_kernel(data.addr3, sizeof(u8) * ETH_ALEN, mac->addr3);
    bpf_probe_read_kernel(data.addr4, sizeof(u8) * ETH_ALEN, mac->addr4);
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    data.skb = skb;

    u32 tid = (u32)bpf_get_current_pid_tgid();
    pass.insert(&tid, &data);
    return 0;
}


int kprobe__mesh_path_add(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct DataOut *data = pass.lookup(&tid);
    if (data == NULL) {
        return 0;
    }

    struct DataOut out = {};
    bpf_probe_read_kernel(&out, sizeof(struct DataOut), data);
    data_out.perf_submit(ctx, &out, sizeof(struct DataOut));

    pass.delete(&tid);
    return 0;
}
