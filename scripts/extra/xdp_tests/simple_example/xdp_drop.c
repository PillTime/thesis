#include <linux/bpf.h>       // access to XDP commands
#include <bpf/bpf_helpers.h> // allow use of SEC() helper
                             // (put part of the compiled object in specific section of the ELF)

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
