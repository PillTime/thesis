#include <uapi/linux/if_ether.h>
#include <uapi/linux/if.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>

// VVVVV debian can't find these VVVVV
#include <../net/mac80211/ieee80211_i.h>
#include <../net/mac80211/mesh.h>


// `egrep -r <thing> /usr/src/linux-lts/include`
//
// define\s+ETH_ALEN --------------------> uapi/linux/if_ether.h
// define\s+IFNAMSIZ --------------------> uapi/linux/if.h
// struct\s+sk_buff\s*{ -----------------> linux/skbuff.h
// struct\s+ieee80211_hdr\s*{ -----------> linux/ieee80211.h
// struct\s+ieee80211_hdr_3addr\s*{ -----> linux/ieee80211.h
// struct\s+ieee80211_mgmt\s*{ ----------> linux/ieee80211.h
// struct\s+ieee80211_sub_if_data\s*{ ---> [N/A]
// struct\s+mesh_path\s*{ ---------------> [N/A]
// struct\s+sta_info\s*{ ----------------> [N/A]


enum Action {
    ACT_TX_ADD = 1,
    ACT_TX_ASG,
    ACT_TX_CHG,
    ACT_TX_ADD_ASG,
    ACT_TX_DEL,
    ACT_RX_ADD,
    ACT_RX_ASG,
    ACT_RX_CHG,
    ACT_RX_ADD_ASG,
    ACT_RX_DEL,
    ACT_US_ASG,
    ACT_US_ADD_ASG,
    ACT_US_CHG,
    ACT_US_DEL,
};

enum Situation {
    SIT_RX = 1,
    SIT_ADD,
    SIT_ASG,
    SIT_CHG,
    SIT_ADD_ASG,
    SIT_DEL,
    SIT_US,
};
BPF_HASH(state, u32, u32);

struct DataOut {
    u8 mac[ETH_ALEN];
    char iface[IFNAMSIZ];
    u64 ts_action;
    u64 ts_txrx;
    u8 action;
    u16 frm_ctrl;
    u16 seq_ctrl;
    u16 qos_ctrl;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    u8 addr4[ETH_ALEN];
    u8 dst[ETH_ALEN];
    u8 old_nh[ETH_ALEN];
    u8 new_nh[ETH_ALEN];
};
BPF_HASH(pass, u32, struct DataOut);
BPF_PERF_OUTPUT(dataout);


static inline void _copy_mac(struct DataOut *data, struct ieee80211_hdr *mac)
{
    data->frm_ctrl = mac->frame_control;
    data->seq_ctrl = mac->seq_ctrl;
    bpf_probe_read_kernel(data->addr1, sizeof(u8) * ETH_ALEN, mac->addr1);
    bpf_probe_read_kernel(data->addr2, sizeof(u8) * ETH_ALEN, mac->addr2);
    bpf_probe_read_kernel(data->addr3, sizeof(u8) * ETH_ALEN, mac->addr3);

    u16 hasqos = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA;
    u16 checkqos = IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA;
    u16 check4addr = IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS;
    if ((mac->frame_control & check4addr) == check4addr) {
        bpf_probe_read_kernel(data->addr4, sizeof(u8) * ETH_ALEN, mac->addr4);
        if ((mac->frame_control & checkqos) == hasqos) {
            bpf_probe_read_kernel(&data->qos_ctrl, 2, (u8 *)mac + sizeof(struct ieee80211_hdr));
        }
    } else if ((mac->frame_control & checkqos) == hasqos) {
        bpf_probe_read_kernel(&data->qos_ctrl, 2, (u8 *)mac + sizeof(struct ieee80211_hdr_3addr));
    }
}


TRACEPOINT_PROBE(net, net_dev_xmit)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation *status = state.lookup(&tid);
    struct DataOut *stored_data = pass.lookup(&tid);
    if (status == NULL || stored_data == NULL) {
        if (status != NULL) {
            state.delete(&tid);
        } else if (stored_data != NULL) {
            pass.delete(&tid);
        }
        return 0;
    }

    struct DataOut data = {};
    bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);

    if (*status == SIT_ADD) {
        data.action = ACT_TX_ADD;
    } else if (*status == SIT_ASG) {
        data.action = ACT_TX_ASG;
    } else if (*status == SIT_CHG) {
        data.action = ACT_TX_CHG;
    } else if (*status == SIT_ADD_ASG) {
        data.action = ACT_TX_ADD_ASG;
    } else if (*status == SIT_DEL) {
        data.action = ACT_TX_DEL;
    }

    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    _copy_mac(&data, mac);
    data.ts_txrx = ts;

    dataout.perf_submit(args, &data, sizeof(struct DataOut));

    state.delete(&tid);
    pass.delete(&tid);

    return 0;
}


int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, void *arg1, struct sk_buff *skb)
{
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;

    if ((mgmt->frame_control & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_ACTION) {
        u64 ts = bpf_ktime_get_ns();
        u32 tid = (u32)bpf_get_current_pid_tgid();
        enum Situation sit = SIT_RX;

        struct DataOut data = {};
        _copy_mac(&data, (struct ieee80211_hdr *)mgmt);
        data.ts_txrx = ts;

        state.update(&tid, &sit);
        pass.update(&tid, &data);
    }

    return 0;
}


int kretprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    // how did we even get here?
    enum Situation *status = state.lookup(&tid);
    struct DataOut *stored_data = pass.lookup(&tid);
    if (status == NULL || stored_data == NULL) {
        if (status != NULL) {
            state.delete(&tid);
        } else if (stored_data != NULL) {
            pass.delete(&tid);
        }
        return 0;
    }

    // something happened, but it's something we don't care about
    if (*status == SIT_RX) {
        state.delete(&tid);
        pass.delete(&tid);
        return 0;
    }

    struct DataOut data = {};
    bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);

    // something happened that we care about
    if (*status == SIT_ADD) {
        data.action = ACT_RX_ADD;
    } else if (*status == SIT_ASG) {
        data.action = ACT_RX_ASG;
    } else if (*status == SIT_CHG) {
        data.action = ACT_RX_CHG;
    } else if (*status == SIT_ADD_ASG) {
        data.action = ACT_RX_ADD_ASG;
    } else if (*status == SIT_DEL) {
        data.action = ACT_RX_DEL;
    }

    dataout.perf_submit(ctx, &data, sizeof(struct DataOut));

    state.delete(&tid);
    pass.delete(&tid);

    return 0;
}


int kprobe__mesh_path_add(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, const u8 *dst)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct DataOut data = {};
    enum Situation sit = SIT_ADD;

    enum Situation *status = state.lookup(&tid);
    if (status != NULL) {
        if (*status == SIT_US || *status == SIT_RX) {
            struct DataOut *stored_data = pass.lookup(&tid);
            if (stored_data == NULL) {
                state.delete(&tid);
                return 0;
            }
            bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);
        } else {
            state.delete(&tid);
            pass.delete(&tid);
            return 0;
        }
    }

    data.ts_action = ts;
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sdata->name);
    bpf_probe_read_kernel(data.dst, sizeof(u8) * ETH_ALEN, dst);

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


int kprobe__mesh_path_assign_nexthop(struct pt_regs *ctx, struct mesh_path *mpath, struct sta_info *sta)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct DataOut data = {};
    enum Situation sit;

    enum Situation *status = state.lookup(&tid);
    if (status != NULL) {
        if (*status == SIT_US || *status == SIT_RX) {
            struct DataOut *stored_data = pass.lookup(&tid);
            if (stored_data == NULL) {
                state.delete(&tid);
                return 0;
            }
            bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);
        } else if (*status == SIT_ADD) {
            struct DataOut *stored_data = pass.lookup(&tid);
            if (stored_data == NULL) {
                state.delete(&tid);
                return 0;
            }
            bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);
            bpf_probe_read_kernel(data.new_nh, sizeof(u8) * ETH_ALEN, sta->addr);
            sit = SIT_ADD_ASG;
            state.update(&tid, &sit);
            pass.update(&tid, &data);
            return 0;
        } else {
            state.delete(&tid);
            pass.delete(&tid);
            return 0;
        }
    }

    data.ts_action = ts;
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sta->sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sta->sdata->name);

    bpf_probe_read_kernel(data.dst, sizeof(u8) * ETH_ALEN, mpath->dst);
    bpf_probe_read_kernel(data.new_nh, sizeof(u8) * ETH_ALEN, sta->addr);
    if (mpath->next_hop == NULL) {
        sit = SIT_ASG;
    } else {
        sit = SIT_CHG;
        bpf_probe_read_kernel(data.old_nh, sizeof(u8) * ETH_ALEN, mpath->next_hop->addr);
    }

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


int kprobe__mesh_path_del(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata, const u8 *addr)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();

    struct DataOut data = {};
    enum Situation sit = SIT_DEL;

    enum Situation *status = state.lookup(&tid);
    if (status != NULL) {
        if (*status == SIT_US || *status == SIT_RX) {
            struct DataOut *stored_data = pass.lookup(&tid);
            if (stored_data == NULL) {
                state.delete(&tid);
                return 0;
            }
            bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);
        } else {
            state.delete(&tid);
            pass.delete(&tid);
            return 0;
        }
    }

    data.ts_action = ts;
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sdata->name);
    bpf_probe_read_kernel(data.dst, sizeof(char) * IFNAMSIZ, addr);

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


TRACEPOINT_PROBE(cfg80211, rdev_add_mpath)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation sit = SIT_US;
    struct DataOut data = {};
    data.action = ACT_US_ADD_ASG;

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


TRACEPOINT_PROBE(cfg80211, rdev_change_mpath)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation sit = SIT_US;
    struct DataOut data = {};
    data.action = ACT_US_CHG;

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


TRACEPOINT_PROBE(cfg80211, rdev_del_mpath)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation sit = SIT_US;
    struct DataOut data = {};
    data.action = ACT_US_DEL;

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


TRACEPOINT_PROBE(cfg80211, rdev_return_int)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation *status = state.lookup(&tid);
    struct DataOut *stored_data = pass.lookup(&tid);
    if (status == NULL || stored_data == NULL) {
        if (status != NULL) {
            state.delete(&tid);
        } else if (stored_data != NULL) {
            pass.delete(&tid);
        }
        return 0;
    }

    struct DataOut data = {};
    bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);

    if (*status == SIT_ASG) {
        data.action = ACT_US_ASG;
    } else if (*status == SIT_CHG) {
        data.action = ACT_US_CHG;
    }

    dataout.perf_submit(args, &data, sizeof(struct DataOut));

    state.delete(&tid);
    pass.delete(&tid);

    return 0;
}
