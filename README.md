# x402 Health Oracle

**Kernel-level L2 health oracle with 4-channel AI agent distribution. x402 micropayments on Base + Hedera.**

Live: `https://rtt.phoenix-ai.work` | npm: [`phoenix-mcp-server`](https://www.npmjs.com/package/phoenix-mcp-server) | MCP Registry: [`io.github.kant19801201behax5/phoenix-mcp-server`](https://registry.modelcontextprotocol.io)

## Problem

AI agents making autonomous on-chain transactions have no way to check network health before committing funds. 64% of DeFi protocols don't verify sequencer health. Base went down for 2 hours in June 2026 with $10.95B at risk.

Existing solutions (Chainlink L2 Sequencer Feed) give binary up/down with 30-second OCR updates. Agents need nanosecond-precision RTT, revert ratios, and stall detection — **before** signing a transaction.

## Solution: One Core, Four Entrances

```
                    ┌── MCP Server (Claude/Cursor/Windsurf)
                    │
Agent ──────────────┼── Olas Mech (DeFi/arbitrage agents)
                    │
                    ├── Direct HTTP/x402 (any agent by URL)
                    │
                    └── RPC Gateway (transparent proxy)
                           │
                           ▼
                    PHOENIX CORE
                    ├── x402 paywall ($0.01/query)
                    ├── 12-chain RTT probe (2s interval)
                    ├── BLAKE3+Ed25519 integrity signing
                    ├── Isolation Forest anomaly scoring
                    └── eBPF XDP enforcement (prog 5437, live)
```

## Distribution Channels

| Channel | Status | How agents find us |
|---------|--------|-------------------|
| **MCP Registry** | **Published** | AI coding assistants discover `preflight_network_health` tool semantically |
| **Olas Mech** | **Code ready** (on-chain pending) | DeFi agents find us in Mech marketplace (425 daily active agents) |
| **Direct x402** | **Live** | Any agent calls `rtt.phoenix-ai.work` with x402 payment |
| **RPC Gateway** | **Live** | Agent uses our URL as RPC endpoint — doesn't know Phoenix exists |

## Chains Monitored

12 L2 networks with 2-second sampling interval:

| Chain | Type | Chain | Type |
|-------|------|-------|------|
| Base | OP Stack | Scroll | zkEVM |
| Arbitrum | Nitro | Mantle | OP Stack |
| Optimism | OP Stack | Linea | zkEVM |
| zkSync | zkEVM | Blast | OP Stack |
| Mode | OP Stack | Taiko | Based rollup |
| Polygon zkEVM | zkEVM | **Casper** | L1 PoS |

Casper is included as an L1 reference chain — the autonomous `casper-agent` service runs DeFi operations on Casper network, protected by the same eBPF kernel sandbox.

## x402 Payment Rails

| Network | Facilitator | Status |
|---------|-------------|--------|
| Base mainnet (`eip155:8453`) | Coinbase CDP | **Live** — $0.02 USDC settled |
| Hedera testnet | Blocky402 | **Integrated** |

```bash
# Try it — returns 402 Payment Required with x402 challenge
curl -i https://rtt.phoenix-ai.work/api/v1/health

# Free health endpoint (no payment)
curl https://rtt.phoenix-ai.work/api/health
```

### Paid Endpoints ($0.01 USDC each)

| Endpoint | Description |
|----------|-------------|
| `/api/v1/health` | Full health snapshot (all 12 chains) |
| `/api/v1/safe` | PASS/DEGRADED/FAIL verdict |
| `/api/v1/price` | Pricing with MEV surge multiplier |
| `/api/v1/chains/{chain}` | Single-chain telemetry |
| `/api/v1/classify` | Agent classification (HUMAN/LEGIT_AGENT/MALICIOUS_BOT) |
| `/api/v1/health-proof` | ZK-lite verifiable proof of node health |

## Components

| Component | File | Description |
|-----------|------|-------------|
| **x402 Gateway** | `gateway/x402_gateway.py` | FastAPI payment gateway — CDP (Base) + Blocky402 (Hedera) |
| **Multi-Chain Probe** | `probe/multi_chain_probe.py` | 12-chain RPC poller (eth_blockNumber every 2s) |
| **WSS Distributor** | `probe/wss_distributor.py` | WebSocket broadcast with BLAKE3+Ed25519 integrity signing |
| **Silicon DNA** | `gateway/server.ts` | 14-layer anti-bot (ML-KEM-768, Argon2 PoW, Spearman correlation) |
| **XDP Threat Filter** | `ebpf/xdp_threat_filter.c` | Kernel-speed packet drop for banned IPs |
| **LSM Agent Guard** | `ebpf/lsm_agent_guard.c` | Syscall-level sandbox: block execve, restrict network |
| **MCP Server** | `mcp-server/` | Model Context Protocol server for AI agent discovery |
| **RPC Gateway** | `gateway/rpc_gateway.py` | Transparent health-checking proxy before upstream RPC |
| **Mech Tool** | `mech-tool/phoenix_health_check.py` | Olas Mech marketplace tool interface |

## eBPF Kernel Security

### XDP Threat Filter (LIVE since Aug 28, 2026)

eBPF XDP program (`prog id 5437`) on `eth0` drops malicious packets before the TCP stack (~5-20µs on virtio_net generic mode). Silicon DNA's 14-layer bot detection feeds the BPF map every 5 seconds.

### LSM Agent Guard (compiled, kernel-ready)

BPF LSM hooks create a per-agent syscall sandbox:
- **Block execve** — agent can't spawn child processes
- **Restrict connect** — only ports 443 (HTTPS) and 8545 (RPC)
- **File access** — limited to agent's working directory

## MCP Server (AI Agent Discovery)

Published to npm and MCP Registry. Any AI coding assistant can discover and use our health oracle.

```bash
# Install from npm
npm install -g phoenix-mcp-server

# Or add to Claude Desktop (claude_desktop_config.json):
{
  "mcpServers": {
    "phoenix-zero": {
      "command": "npx",
      "args": ["phoenix-mcp-server"]
    }
  }
}
```

**Tool:** `preflight_network_health` — returns PASS / DEGRADED / FAIL with kernel-level evidence.

## RPC Gateway (Transparent Proxy)

Agent connects to Phoenix as if it were a normal RPC endpoint. Phoenix checks health before forwarding:

```
Agent → POST /rpc/base {"method": "eth_sendRawTransaction", ...}
     Phoenix checks health:
       PASS → forward to upstream RPC → response + X-Phoenix-Health: PASS
       DEGRADED → forward + X-Phoenix-Warning header
       FAIL → 503 "Transaction blocked to protect funds"
```

**Live — try it now:**

```bash
curl -X POST https://rtt.phoenix-ai.work/rpc/base \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
# → {"jsonrpc":"2.0","result":"0x...","id":1}
# + X-Phoenix-Health: PASS header
```

Supported chains: `base`, `arbitrum`, `optimism`, `zksync`, `scroll`, `mantle`, `linea`, `blast`, `mode`, `taiko`, `polygon_zkevm`.

## Docker

Runs the x402 gateway locally. Real-time telemetry comes from the production server at `rtt.phoenix-ai.work`.

```bash
cp .env.example .env   # edit with your CDP/Hedera keys
docker compose up
curl -i localhost:3002/v1/safe       # → 402 Payment Required
curl localhost:3002/                  # → service info
```

## Security Stack

- **eBPF XDP** — kernel-speed threat response (live, prog 5437)
- **eBPF LSM** — per-agent syscall sandbox (compiled)
- **ML-KEM-768** (NIST FIPS 203) post-quantum key exchange
- **BLAKE3 + Ed25519** integrity signing on all telemetry
- **14-layer bot detection** — CPU jitter, Spearman correlation, Argon2 PoW, Frankenstein headers, Sybil clustering, Privacy Pass
- **Isolation Forest** anomaly scoring

## Test Suite

- **Main repo:** 29 test files, 581 passed, 0 failed, 1 skipped
- **Hackathon repo:** 3 test suites, 31 passed (gateway 21 + MCP server 10)
- **Python tests:** 8 passed (gateway config)
- **Total: 620+ tests**

## Verified Revenue

Two on-chain settlements on Base mainnet (Sep 1, 2026):
- $0.01 + $0.01 = **$0.02 USDC total**
- PAY_TO: `0xbb967F16C7f3e9B4c1626680684445d41dBE44Ab`

## Continuity

This project extends 6+ months of production work (since March 2026). Server uptime 117+ days. 11 production services on DigitalOcean. See [CONTINUITY_PROOF.md](CONTINUITY_PROOF.md).

## Paper

Silicon DNA: The Physics of Network Identity Verification
DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862)

## License

MIT
