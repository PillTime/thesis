#include <uapi/linux/ptrace.h>
#include <../net/mac80211/mesh.h>


/*BPF_PERF_OUTPUT(out);
struct data_t {
    u8 *src;
    u8 *dst;
};*/


int kretprobe__mesh_path_add(struct pt_regs *ctx)
{
    //struct data_t data = {};

    struct mesh_path *path = (struct mesh_path *)PT_REGS_RC(ctx);
    //data.src = path->sdata->vif.addr;
    //data.dst = path->dst;

    bpf_trace_printk("%s\n", sizeof(path->dst));

    //out.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
