#!/usr/bin/python3

from bcc import BPF
import scapy.all as scp


# map for DataOut field filling
#
# mac .. ts              : ADD & ASSIGN
# action                 : TX & RX(finish)
# frm_ctrl .. addr4      : TX & RX(start)


b = BPF(text='''
#include <uapi/linux/if.h>               // IFNAMSIZ
#include <uapi/linux/if_ether.h>         // ETH_ALEN
#include <../net/mac80211/ieee80211_i.h> // struct ieee80211_sub_if_data


enum Action {
    ACT_TX_ADD_ASG = 1,
    ACT_TX_ADD,
    ACT_TX_ASG,
    ACT_RX_ADD_ASG,
    ACT_RX_ADD,
    ACT_RX_ASG,
};

enum Situation {
    SIT_RX = 1,
    SIT_ADD,
    SIT_ASG,
    SIT_ADD_ASG,
};
BPF_HASH(state, u32, u32);

struct DataOut {
    u8 mac[ETH_ALEN];
    char iface[IFNAMSIZ];
    u64 ts;
    u8 action;
    u16 frm_ctrl;
    u16 seq_ctrl;
    u16 qos_ctrl;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    u8 addr4[ETH_ALEN];
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
            bpf_probe_read_kernel(&data->qos_ctrl, 2, mac + sizeof(struct ieee80211_hdr));
        }
    } else if ((mac->frame_control & checkqos) == hasqos) {
        bpf_probe_read_kernel(&data->qos_ctrl, 2, mac + sizeof(struct ieee80211_hdr_3addr));
    }
}


TRACEPOINT_PROBE(net, net_dev_xmit)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    u32 *status = state.lookup(&tid);
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
    } else if (*status == SIT_ADD_ASG) {
        data.action = ACT_TX_ADD_ASG;
    }

    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    struct ieee80211_hdr *mac = (struct ieee80211_hdr *)skb->data;

    _copy_mac(&data, mac);

    dataout.perf_submit(args, &data, sizeof(struct DataOut));

    state.delete(&tid);
    pass.delete(&tid);

    return 0;
}


int kprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx, void *arg1, struct sk_buff *skb)
{
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)skb->data;

    if ((mgmt->frame_control & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_ACTION) {
        u32 tid = (u32)bpf_get_current_pid_tgid();
        enum Situation sit = SIT_RX;

        struct DataOut data = {};
        _copy_mac(&data, (struct ieee80211_hdr *)mgmt);

        state.update(&tid, &sit);
        pass.update(&tid, &data);
    }

    return 0;
}


int kretprobe__ieee80211_mesh_rx_queued_mgmt(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    // how did we even get here?
    u32 *status = state.lookup(&tid);
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
    } else if (*status == SIT_ADD_ASG) {
        data.action = ACT_RX_ADD_ASG;
    }

    dataout.perf_submit(ctx, &data, sizeof(struct DataOut));

    state.delete(&tid);
    pass.delete(&tid);

    return 0;
}


int kprobe__mesh_path_add(struct pt_regs *ctx, struct ieee80211_sub_if_data *sdata)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation sit = SIT_ADD;
    struct DataOut data = {};

    u32 *status = state.lookup(&tid);
    if (status != NULL) {
        if (*status == SIT_RX) {
            struct DataOut *stored_data = pass.lookup(&tid);
            if (stored_data != NULL) {
                bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);
            }
        } else {
            state.delete(&tid);
            pass.delete(&tid);
            return 0;
        }
    }

    data.ts = ts;
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sdata->name);

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}


int kprobe__mesh_path_assign_nexthop(struct pt_regs *ctx, void *arg1, struct sta_info *sta)
{
    u64 ts = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();

    enum Situation sit = SIT_ASG;
    struct DataOut data = {};

    u32 *status = state.lookup(&tid);
    if (status != NULL) {
        if (*status == SIT_ADD) {
            sit = SIT_ADD_ASG;
            state.update(&tid, &sit);
            return 0;
        } else if (*status == SIT_RX) {
            struct DataOut *stored_data = pass.lookup(&tid);
            if (stored_data != NULL) {
                bpf_probe_read_kernel(&data, sizeof(struct DataOut), stored_data);
            }
        } else {
            state.delete(&tid);
            pass.delete(&tid);
            return 0;
        }
    }

    data.ts = ts;
    bpf_probe_read_kernel(data.mac, sizeof(u8) * ETH_ALEN, sta->sdata->vif.addr);
    bpf_probe_read_kernel(data.iface, sizeof(char) * IFNAMSIZ, sta->sdata->name);

    state.update(&tid, &sit);
    pass.update(&tid, &data);

    return 0;
}
''')


ACTIONS = [
    "UNKNOWN",
    "TX - add with nexthop",
    "TX - add without nexthop",
    "TX - set nexthop",
    "RX - add with nexthop",
    "RX - add without nexthop",
    "RX - set nexthop"
]


def printer(cpu, data, size):
    info = b["dataout"].event(data)

    qos_ctrl = None
    addr4 = None

    hasqos = 0x0008 | 0x0080
    checkqos = 0x000c | 0x0080
    if (info.frm_ctrl & checkqos) == hasqos:
        qos_ctrl = hex(info.qos_ctrl)
    check4addr = 0x0100 | 0x0200
    if (info.frm_ctrl & check4addr) == check4addr:
        addr4 = list(info.addr4)

    print("action:    {}".format(ACTIONS[info.action]))
    print("interface: {}".format(str(info.iface, "UTF-8")))
    print("mac:       {}".format(list(info.mac)))
    print("ts:        {}".format(info.ts))
    print("sequence:  {}".format(hex(info.seq_ctrl)))
    print("frame:     {}".format(hex(info.frm_ctrl)))
    print("qos:       {}".format(qos_ctrl))
    print("addr1:     {}".format(list(info.addr1)))
    print("addr2:     {}".format(list(info.addr2)))
    print("addr3:     {}".format(list(info.addr3)))
    print("addr4:     {}".format(addr4))
    print()


b["dataout"].open_perf_buffer(printer)
print("READY")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        b["pass"].clear()
        b["state"].clear()
        exit()
