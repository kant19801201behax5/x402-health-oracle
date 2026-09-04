# eBPF Security Layer — Silicon DNA × Phoenix Zero

Kernel-level enforcement modules that extend Silicon DNA's userspace bot detection
into the Linux kernel via eBPF.

## Components

### 1. XDP Threat Filter (`xdp_threat_filter.c`)

Drops packets from banned IPs at the NIC driver level — before the TCP/IP stack
allocates a socket or buffer. The userspace loader (`xdp_loader.py`) syncs
Silicon DNA's ban list into a BPF hash map every 5 seconds.

**Architecture:**

```
phoenix_userspace_sensor.py  →  /api/agent/interact  →  phoenixThreatScore
                                                             ↓
bannedIPs (server.ts)  →  /api/admin/xdp-sync  →  xdp_loader.py
                                                       ↓
                                              BPF map: blocked_ips
                                                       ↓
                                              XDP program on eth0
                                              XDP_DROP / XDP_PASS
```

**Performance:**
- Generic mode (virtio_net, cloud VPS): ~5–20 µs per packet
- Native mode (Intel/Mellanox bare-metal): ~100–300 ns per packet
- Both are faster than iptables/nftables (which operate after socket allocation)

**Build & Run:**

```bash
# Compile
clang-14 -O2 -g -target bpf -c xdp_threat_filter.c -o xdp_threat_filter.o

# Attach (generic mode — works on any NIC driver)
ip link set dev eth0 xdpgeneric obj xdp_threat_filter.o sec xdp

# Start the loader (syncs ban list from Silicon DNA)
python3 xdp_loader.py --attach --detach-on-exit

# Or via systemd
cp xdp-shield.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now xdp-shield
```

**Verify:**

```bash
# Check XDP is attached
ip link show eth0 | grep xdp

# Check BPF map contents
bpftool map dump name blocked_ips

# Check loader sync
curl -s http://localhost:3001/api/admin/xdp-sync | python3 -m json.tool
```

### 2. LSM Agent Guard (`lsm_agent_guard.c`)

BPF LSM program that sandboxes the Casper autonomous agent (`casper-agent.service`)
at the kernel level. Restricts the agent's process to:
- Network: only outbound connections to ports 443 (HTTPS/RPC) and 8545 (JSON-RPC)
- Filesystem: read/write only within `/opt/casper-agent/`
- Execution: blocks `execve` of any new binary (prevents prompt-injection escalation)

**Why this matters:** AI agents that transact autonomously (x402 payments, on-chain
calls) are a new attack surface. A prompt-injection exploit that compromises the
agent's decision loop is useless if the kernel blocks the resulting system calls.
This is defense-in-depth at the OS layer — the agent can only do what its policy allows,
regardless of what its inputs tell it to do.

See `lsm_agent_guard.c` for the implementation and `lsm-guard.service` for deployment.

## Requirements

- Linux kernel ≥ 5.7 with `CONFIG_BPF_LSM=y`, `CONFIG_XDP_SOCKETS=y`, `CONFIG_DEBUG_INFO_BTF=y`
- `clang` (≥ 12), `bpftool`, `libbpf` headers
- Root privileges for BPF program loading

**DO NYC1 droplet (Ubuntu 22.04, kernel 5.15.0-171):** all requirements met.
`CONFIG_BPF_LSM=y` ✓, `CONFIG_XDP_SOCKETS=y` ✓, `CONFIG_DEBUG_INFO_BTF=y` ✓,
`bpftool` installed ✓, `clang-14` installed ✓.
