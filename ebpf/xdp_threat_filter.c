/*
 * XDP Threat Filter — kernel-level packet drop for Silicon DNA banned IPs.
 *
 * Operates at the NIC driver level (before the TCP/IP stack).
 * Userspace loader writes banned IPv4 addresses into the BPF hash map;
 * this program drops matching source IPs with XDP_DROP.
 *
 * Build:
 *   clang-14 -O2 -g -target bpf -c xdp_threat_filter.c -o xdp_threat_filter.o
 *
 * Attach (generic mode, works on virtio_net):
 *   ip link set dev eth0 xdpgeneric obj xdp_threat_filter.o sec xdp
 *
 * Detach:
 *   ip link set dev eth0 xdpgeneric off
 *
 * Performance: generic mode on virtio_net ≈ 5–20 µs per packet.
 * Native mode on bare-metal NICs (Intel/Mellanox) ≈ 100–300 ns.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* BPF helper definitions — keeps this file self-contained without libbpf headers */
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#define SEC(name) __attribute__((section(name), used))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/* Hash map: key = __be32 (IPv4 src), value = __u32 (1 = blocked) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_threat_drop(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet header bounds check */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* IPv4 header bounds check */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* Lookup source IP in blocked map */
    __u32 src_ip = iph->saddr;
    __u32 *val = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (val && *val == 1)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
