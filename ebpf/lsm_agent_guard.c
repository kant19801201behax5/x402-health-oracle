/*
 * LSM Agent Guard — kernel-level sandbox for autonomous AI agents.
 *
 * Uses BPF LSM hooks to restrict a specific PID (the casper-agent process):
 *   - bprm_check_security: blocks execve of any new binary
 *   - file_open: pass-through (file ACLs via seccomp overlay)
 *   - socket_connect: allows only outbound TCP to ports 443 and 8545
 *
 * The guarded PID is written by the userspace loader into the BPF map
 * `agent_policy`. Key = __u32 pid, Value = __u32 (1 = guarded).
 *
 * Build:
 *   clang-14 -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
 *       -c lsm_agent_guard.c -o lsm_agent_guard.o
 *
 * Load:
 *   bpftool prog load lsm_agent_guard.o /sys/fs/bpf/lsm_agent_guard \
 *       type lsm attach_type lsm
 *
 * Requires: CONFIG_BPF_LSM=y, lsm=...,bpf in boot cmdline or /etc/default/grub
 */

#include <linux/bpf.h>
#include <linux/types.h>

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

#define SEC(name) __attribute__((section(name), used))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 113;

/* Map: key = PID (__u32), value = 1 if guarded */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} agent_policy SEC(".maps");

/* Map: allowed destination ports for guarded processes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ports SEC(".maps");

static __always_inline int is_guarded(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 *val = bpf_map_lookup_elem(&agent_policy, &pid);
    return val && *val == 1;
}

/*
 * Block execve for guarded PIDs.
 * LSM BPF programs receive arguments via ctx pointer (BPF trampoline).
 * For bprm_check_security: ctx[0] = struct linux_binprm *, return = int.
 * We only need PID check — args are unused.
 */
SEC("lsm/bprm_check_security")
int agent_block_exec(void *ctx)
{
    if (!is_guarded())
        return 0;

    return -1;  /* -EPERM: deny execve for guarded process */
}

/*
 * File access hook — pass-through for now.
 * Fine-grained file ACLs are enforced via the loader's seccomp overlay.
 * This hook exists as a registration point for future path-based filtering.
 */
SEC("lsm/file_open")
int agent_file_guard(void *ctx)
{
    return 0;
}

/*
 * Restrict outbound connections to allowed ports only.
 * For socket_connect: ctx[0] = struct socket *, ctx[1] = struct sockaddr *,
 * ctx[2] = addrlen. We read the sockaddr to extract the port.
 */
SEC("lsm/socket_connect")
int agent_net_guard(void *ctx)
{
    if (!is_guarded())
        return 0;

    /* ctx is array of __u64: [0]=socket, [1]=sockaddr_ptr, [2]=addrlen */
    __u64 *args = (__u64 *)ctx;
    void *addr_ptr;
    bpf_probe_read_kernel(&addr_ptr, sizeof(addr_ptr), &args[1]);

    if (!addr_ptr)
        return 0;

    /* Read address family (first 2 bytes of sockaddr) */
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), addr_ptr);

    /* Only filter AF_INET (2) and AF_INET6 (10) */
    if (family != 2 && family != 10)
        return 0;

    /* Read destination port (bytes 2-3 of sockaddr, network byte order) */
    __u16 port_be = 0;
    bpf_probe_read_kernel(&port_be, sizeof(port_be), addr_ptr + 2);

    /* Convert from network byte order (big-endian) to host */
    __u32 port = ((__u32)(port_be & 0xFF) << 8) | ((__u32)(port_be >> 8));

    /* Check if port is in allowed set */
    __u32 *allowed = bpf_map_lookup_elem(&allowed_ports, &port);
    if (!allowed)
        return -1;  /* -EPERM: port not in allowlist */

    return 0;
}

char _license[] SEC("license") = "GPL";
