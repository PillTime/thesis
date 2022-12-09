#include <stdint.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>


struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	uint8_t addr1[ETH_ALEN];
	uint8_t addr2[ETH_ALEN];
	uint8_t addr3[ETH_ALEN];
	__le16 seq_ctrl;
	uint8_t addr4[ETH_ALEN];
} __packed __attribute__((aligned (2)));


SEC("xdp_info")
int xdp_info_func(struct xdp_md *ctx)
{
    // pointers to start and end of raw packet data
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;

    // check if we go out of bounds
    // (won't allow to insert prog) if no check is made)
    if ((void *)hdr + sizeof(*hdr) > data_end) {
        return XDP_PASS;
    }

    bpf_printk("fc: 0x%04x", hdr->frame_control);
    bpf_printk("sc: 0x%04x", hdr->seq_ctrl);
    bpf_printk("");

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
