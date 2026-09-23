# x402 Health Oracle

**Execution oracle for AI agents: tells you — before you sign — whether your transaction or payment will land on time, or be delayed, stalled or reverted. 12 chains, measured every 2 s from the kernel up. Every answer is signed and backed by L1/L2/L3 evidence records. Pay per call via x402 (Base, Polygon, Arbitrum USDC).**

[![M8ven Verified](https://m8ven.ai/badge/mcp/kant19801201behax5/x402-health-oracle?variant=verified)](https://m8ven.ai/mcp/kant19801201behax5/x402-health-oracle)

Live: `https://rtt.phoenix-ai.work` | npm: [`phoenix-mcp-server`](https://www.npmjs.com/package/phoenix-mcp-server) | MCP Registry: [`io.github.kant19801201behax5/phoenix-mcp-server`](https://registry.modelcontextprotocol.io)

## Problem

AI agents making autonomous on-chain transactions have no way to check network health before committing funds. 64% of DeFi protocols don't verify sequencer health. Base went down for 2 hours in June 2026 with $10.95B at risk.

Existing solutions (Chainlink L2 Sequencer Feed) give binary up/down with 30-second OCR updates. Agents need nanosecond-precision RTT, revert ratios, and stall detection — **before** signing a transaction.

**What you actually buy:** network delay is visible here *before* it hits you. If a sequencer is stalling or RPC latency is spiking, your swap, bridge or x402 payment will arrive late — or not at all. Phoenix measures that delay right now and answers *act now / wait / route elsewhere*.

### Evidence base: three layers, recorded continuously

| Layer | What is measured | Record types (signed BLAKE3 + Ed25519) |
|---|---|---|
| **L1 — kernel / physical** | eBPF kernel RTT to each chain's RPC, physical timing stats | `PHOENIX_KERNEL_RTT`, `SILICON_DNA_PHY_STATS` |
| **L2 — RPC / network** | p95/p99 latency, stall flag, anomaly score per chain; ETH mempool signal | `PHOENIX_METRIC`, `PHOENIX_ETH_SIGNAL` |
| **L3 — chain / sequencer** | revert ratio, sequencer health, volume delta | `PHOENIX_L2_HEALTH`, `PHOENIX_VOLUME_DELTA` |
| **Cross-layer** | 12×12 Pearson R_xy between chains (correlated failures) | `SILICON_DNA_CORRELATION` |

The server writes ~1.2 GB/day of these records; a paid verdict is derived from them and signed (EIP-191, signer `0xdac8adC44f621bC3A56E9DC108d2F76Be3142294`) so it can be verified offline.

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
                    ├── Surge pricing daemon (3-tier: $0.01/$0.03/$0.10)
                    └── eBPF XDP enforcement (prog 6293, live)
```

## Distribution Channels

| Channel | Status | How agents find us |
|---------|--------|-------------------|
| **MCP Registry** | **Published** | `io.github.kant19801201behax5/phoenix-mcp-server` — tools `check_safety_free`, `preflight_network_health` |
| **MCP Discovery** | **Live** | `/.well-known/mcp.json` — 5 tools (1 free + 4 paid) for LLM agent auto-discovery |
| **npm SDK** | **Published** | `phoenix-zero-preflight` (also `@phoenix-zero/preflight`) — 3-line integration with `createPhoenixTool()` for AgentKit/LangChain |
| **Olas Mech** | **Code ready** (on-chain registration pending) | Mech marketplace tool interface |
| **Direct x402** | **Live** | Any agent calls `rtt.phoenix-ai.work` with x402 payment |
| **Free Demo** | **Live** | `/api/v1/demo/safe` — verdict delayed 60 s, 100 calls/IP/day, no payment |
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

Casper is included as an L1 reference chain (L1 thresholds: stall ≥ 10 s, high latency > 2 s).

## x402 Payment Rails

| Network | Facilitator | Status |
|---------|-------------|--------|
| Base mainnet (`eip155:8453`) | Coinbase CDP | **Live** — USDC settled on-chain |
| Polygon (`eip155:137`) | Coinbase CDP | **Live** |
| Arbitrum One (`eip155:42161`) | Coinbase CDP | **Live** |
| Hedera testnet | Blocky402 | **Integrated** (testnet) |

Every 402 response carries the x402 v2 `PAYMENT-REQUIRED` header **and** the same `x402Version`/`accepts` in the JSON body.

```bash
# Try it — returns 402 Payment Required with x402 challenge
curl -i https://rtt.phoenix-ai.work/api/v1/health

# Free demo — the same verdict, 60 s late (100/day/IP, no payment)
curl https://rtt.phoenix-ai.work/api/v1/demo/safe

# Free current price (surge multiplier)
curl https://rtt.phoenix-ai.work/api/v1/price

# Free health endpoint (no payment)
curl https://rtt.phoenix-ai.work/api/health
```

### Paid Endpoints ($0.01 USDC; surge ×3 = $0.03 when Base p99 > 500 ms or revert > 25%, ×10 = $0.10 on stall ≥ 5 s or revert ≥ 50%)

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/preflight` | **Deterministic execution decision** — PASS/DEGRADED/FAIL with evidence_id |
| `/api/v1/health` | Full health snapshot (all 12 chains) |
| `/api/v1/safe` | **Live** boolean safety verdict + reason, P99, revert ratio |
| `/api/v1/chains/{chain}` | Single-chain telemetry |
| `/api/v1/classify` | Agent classification: HUMAN/LEGIT_AGENT/MALICIOUS_BOT (behavioral timing, not NIC fingerprinting) |
| `/api/v1/correlation` | 12×12 cross-chain Pearson R_xy matrix + Frobenius anomaly score |
| `/api/v1/health-proof` | HMAC-SHA256 integrity commitment + eBPF status (not ZK — requires shared key) |

### Free Endpoints (no payment required)

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/demo/safe` | Safety verdict **delayed 60 s** (100/day/IP) — `{safe, reason, chain, demo: true, delayed_s, as_of, teaser}` |
| `GET /api/v1/price` | Current price and surge multiplier (no verdict) |
| `GET /api/health` | Node health status |
| `GET /.well-known/mcp.json` | MCP 1.0 tool discovery (5 tools) |
| `GET /.well-known/x402` | x402 V2 agent discovery metadata |
| `GET /api/v1/openapi.json` | OpenAPI 3.0 spec (all 9 endpoints) |

## Components

| Component | File | Description |
|-----------|------|-------------|
| **x402 Gateway** | `gateway/x402_gateway.py` | FastAPI payment gateway — CDP (Base, Polygon, Arbitrum) + Blocky402 (Hedera testnet) |
| **Multi-Chain Probe** | `probe/multi_chain_probe.py` | 12-chain RPC poller (eth_blockNumber every 2s) |
| **WSS Distributor** | `probe/wss_distributor.py` | WebSocket broadcast with BLAKE3+Ed25519 integrity signing |
| **Silicon DNA** | `gateway/server.ts` | 9-gate anti-bot (L0-L7 + L1.1/L2.5): CPU jitter, Frankenstein, SNIPER, Spearman ρ, Argon2id PoW, ML-KEM-768, eBPF, Shadow classifier |
| **XDP Threat Filter** | `ebpf/xdp_threat_filter.c` | Kernel-speed packet drop for banned IPs |
| **LSM Agent Guard** | `ebpf/lsm_agent_guard.c` | Syscall-level sandbox: block execve, restrict network |
| **MCP Server** | `mcp-server/` | Model Context Protocol server for AI agent discovery |
| **RPC Gateway** | `gateway/rpc_gateway.py` | Transparent health-checking proxy before upstream RPC |
| **Mech Tool** | `mech-tool/phoenix_health_check.py` | Olas Mech marketplace tool interface |

## eBPF Kernel Security

### XDP Threat Filter (LIVE since Aug 28, 2026)

eBPF XDP program (`prog id 6293`) on `eth0` drops malicious packets before the TCP stack (~5-20µs on virtio_net generic mode). Silicon DNA's 14-layer bot detection feeds the BPF map every 5 seconds.

### LSM Agent Guard (loader running; target service configurable)

BPF LSM program (kernel boot `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`). Sandboxes the service named in `LSM_TARGET_SERVICE` (the original target, `casper-agent`, has been retired; no service is currently attached):
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

**Tools:**
- `check_safety_free` — FREE safety check (100 calls/IP/day). Returns `{safe, reason, chain}` for any of 12 chains.
- `preflight_network_health` — PASS / DEGRADED / FAIL with kernel-level evidence. Free for `health_check`, x402 $0.01 for `rtt_ns`/`revert_ratio`.

## npm SDK — `phoenix-zero-preflight`

3-line integration for bot developers:

```javascript
const { PhoenixPreflight } = require("phoenix-zero-preflight");
const phoenix = new PhoenixPreflight();

// Free demo — no payment needed
const result = await phoenix.checkSafe("base");
// { safe: true, reason: "ok", chain: "base", demo: true }

// For AgentKit / LangChain — drop-in tool
const { createPhoenixTool } = require("phoenix-zero-preflight");
const tool = createPhoenixTool();
// tool.name = "phoenix_preflight_safety"
```

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

- **eBPF XDP** — kernel-speed threat response (live, prog 6293)
- **eBPF LSM** — per-agent syscall sandbox (3 LSM programs; attach target configurable)
- **ML-KEM-768** (NIST FIPS 203) post-quantum key exchange
- **BLAKE3 + Ed25519** integrity signing on all telemetry
- **14-layer bot detection** — CPU jitter, Spearman correlation, Argon2 PoW, Frankenstein headers, Sybil clustering, Privacy Pass
- **Isolation Forest** anomaly scoring (offline-trained, edge inference; `anomaly_score` in every `PHOENIX_METRIC`)

## Test Suite

- **Main repo:** 34 test files, 682 passed, 0 failed, 1 skipped
- **Hackathon repo:** 3 test suites, 31 passed (gateway 21 + MCP server 10)
- **Python tests:** 69 passed (XDP 19 + LSM 31 + sensor 19)
- **Total: 714+ tests**

## Verified Revenue

External (non-owner) x402 settlements on Base mainnet: **$0.03 USDC** (own test payments excluded). Verify on-chain:
- PAY_TO: `0xbb967F16C7f3e9B4c1626680684445d41dBE44Ab`

## Continuity

This project extends 6+ months of production work (since March 2026). Server uptime 170+ days. 13 production services on DigitalOcean. See [CONTINUITY_PROOF.md](CONTINUITY_PROOF.md).

## Paper

Silicon DNA: The Physics of Network Identity Verification
DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862)

## License

MIT
