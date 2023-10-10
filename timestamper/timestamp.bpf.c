#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "timestamp.h"

struct payload{
    uint64_t timestamp;
};

SEC("xdp")
int timestamper(struct xdp_md *ctx)
{
    void *data_end = (void*)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;

    struct ethhdr *eth = (struct ethhdr *)data;
    if(data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    if(eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    uint64_t offset = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr);
    if(data + offset + sizeof(struct payload)> data_end)
        return XDP_PASS;

    struct payload * pl = (struct payload *)(data+offset);
    u_int64_t timestamp = bpf_ktime_get_ns();
    pl->timestamp = timestamp;

    return XDP_PASS; // Packet doesn't meet the criteria, pass it through
}

char LICENSE[] SEC("license") = "GPL";
