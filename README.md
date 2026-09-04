# x402 Health Oracle

**Kernel-level agentic IAM + x402-monetized chain health data.**

Live at: `https://rtt.phoenix-ai.work/api/v1/health`

## Problem

AI agents making autonomous on-chain transactions need two things existing infrastructure doesn't provide:

1. **Reliable chain health data** — agents can't "feel" when a sequencer is degraded; they need objective P99 latency, revert ratios, and stall detection before committing funds.
2. **Kernel-level security boundaries** — when an agent holds signing keys and executes transactions, a compromised process means stolen funds. Traditional OS permissions are too coarse. The 2026 agentic IAM gap is the #1 unsolved security problem in autonomous AI infrastructure.

## Solution

x402 Health Oracle solves both:

- **12-chain real-time health oracle** monetized via x402 micropayments ($0.01 USDC per query) on Base mainnet and Hedera testnet (via Blocky402 facilitator)
- **eBPF kernel-level agent sandbox** — XDP drops malicious traffic in <20µs; LSM hooks enforce per-process syscall policies (block execve, restrict network to ports 443/8545) so a compromised agent can't escalate

```
Agent → GET /api/v1/health
     ← 402 Payment Required (x402 challenge: Base or Hedera)
Agent → pays $0.01 USDC via x402
     ← 200 OK + real-time chain health + execution recommendation
```

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│  multi_chain_probe   │────▶│   wss_distributor     │────▶│  x402_gateway    │
│  12 chains, 2s poll  │     │  BLAKE3+Ed25519 sign  │     │  FastAPI :3002   │
│  eth_blockNumber     │     │  Isolation Forest      │     │  $0.01/query     │
│  eth_getBlockReceipts│     │  anomaly scoring       │     │  7 paid endpoints│
└─────────────────────┘     └──────────────────────┘     └──────────────────┘
         │                                                       │
         │           ┌──────────────────┐                        │
         │           │  eBPF XDP/LSM     │◀───────────────────────┤
         │           │  kernel sandbox   │  threat IPs → BPF map  │
         │           │  agent IAM guard  │  agent PID → policy    │
         │           └──────────────────┘                        │
         │                                                       ▼
         │                                             ┌──────────────────┐
         └────────────────────────────────────────────▶│   server.ts       │
                                                       │  Silicon DNA      │
                                                       │  14-layer bot     │
                                                       │  detection :3001  │
                                                       └──────────────────┘
```

### Components

| Component | File | Description |
|-----------|------|-------------|
| **x402 Gateway** | `gateway/x402_gateway.py` | FastAPI payment gateway — CDP (Base) + Blocky402 (Hedera) |
| **Multi-Chain Probe** | `probe/multi_chain_probe.py` | 12-chain RPC poller (eth_blockNumber every 2s) |
| **WSS Distributor** | `probe/wss_distributor.py` | WebSocket broadcast with BLAKE3+Ed25519 integrity signing |
| **Silicon DNA** | `gateway/server.ts` | 14-layer anti-bot (ML-KEM-768, Argon2 PoW, Spearman correlation) |
| **XDP Threat Filter** | `ebpf/xdp_threat_filter.c` | Kernel-speed packet drop for banned IPs |
| **LSM Agent Guard** | `ebpf/lsm_agent_guard.c` | Syscall-level sandbox: block execve, restrict network |

## x402 Payment Rails

| Network | Facilitator | Chain | Status |
|---------|-------------|-------|--------|
| `eip155:8453` | Coinbase CDP | Base mainnet | **Live** — 2 settlements ($0.02 USDC) |
| `hedera:testnet` | Blocky402 | Hedera testnet | **Integrated** — pending first settlement |

All endpoints cost $0.01 USDC.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Full health snapshot (all 12 chains) |
| `/api/v1/safe` | GET | Boolean: safe to execute? |
| `/api/v1/price` | GET | Current pricing with MEV surge multiplier |
| `/api/v1/chains/{chain}` | GET | Single-chain health |
| `/api/v1/classify` | POST | Agent classification (HUMAN/LEGIT_AGENT/MALICIOUS_BOT) |
| `/api/v1/health-proof` | GET | ZK-lite verifiable proof of node health |

## eBPF: Dynamic Task-Scoped Agentic IAM

The core innovation: eBPF programs enforce **per-agent security policies at the kernel level**, not the application level. This is the missing layer for autonomous AI agents that hold signing keys.

### XDP Threat Filter (LIVE since Aug 28, 2026)

eBPF XDP program on `eth0` drops packets from banned IPs before the TCP stack (~5-20µs on virtio_net generic mode; <1µs native on bare-metal). Silicon DNA's 14-layer bot detection feeds the BPF map every 5 seconds.

### LSM Agent Guard (compiled, kernel-ready)

BPF LSM hooks create a dynamic syscall sandbox per agent process:
- **Block execve** — agent can't spawn child processes (no reverse shells)
- **Restrict connect** — only ports 443 (HTTPS) and 8545 (Ethereum RPC)
- **File access** — read/write limited to agent's working directory
- **Policy updates** — PID + policy written to BPF map, enforced immediately

This solves the agentic IAM gap: traditional RBAC is per-user, not per-task. eBPF LSM enables per-process, per-syscall, dynamically-scoped policies that update without service restart.

## Verified Revenue

Two on-chain settlements on Base mainnet (Sep 1, 2026):
- $0.01 USDC — first x402 payment
- $0.01 USDC — second settlement
- **Total: $0.02 USDC**

PAY_TO: `0xbb967F16C7f3e9B4c1626680684445d41dBE44Ab`

## Security Stack

- **eBPF XDP** — kernel-speed threat response (live)
- **eBPF LSM** — per-agent syscall sandbox (compiled)
- **ML-KEM-768** (NIST FIPS 203) post-quantum key exchange per WebSocket
- **BLAKE3 + Ed25519** integrity signing on all telemetry
- **14-layer bot detection** — CPU jitter, Spearman correlation, Argon2 PoW, Frankenstein header analysis, Sybil clustering, Privacy Pass tokens
- **Isolation Forest** anomaly scoring (numpy-only)

## Continuity

This project extends 6+ months of production work. See [CONTINUITY_PROOF.md](CONTINUITY_PROOF.md) for full before/during table.

## Paper

Silicon DNA: The Physics of Network Identity Verification
DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862)

## License

MIT
