// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_ipv6_filter"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define DEBUG 1

#ifdef  DEBUG
/* Only use this for debug output. Notice output from  bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                     \
        ({                          \
            char ____fmt[] = fmt;               \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);            \
        })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end, uint16_t *eth_type)
{
    uint64_t offset;

    offset = sizeof(*eth);
    if ((void *)eth + offset > data_end) {
        return false;
    }
	*eth_type = eth->h_proto;
	return true;
}

SEC("xdp_dropv6")
int xdp_dropv6_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
	uint16_t eth_type = 0;

	if (!(parse_eth(eth, data_end, &eth_type))) {
        bpf_debug("Debug: Cannot parse L2\n");
        return XDP_PASS;
    }

    bpf_debug("Debug: eth_type:0x%x\n", ntohs(eth_type));
	if (eth_type == ntohs(0x86dd)) {
		return XDP_PASS;
	} else {
		return XDP_DROP;
	}
}

char _license[] SEC("license") = "GPL";
