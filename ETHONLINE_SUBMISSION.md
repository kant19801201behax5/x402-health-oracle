# ETHOnline 2026 — Submission Materials

## Project Title
Phoenix Zero: Kernel-Level L2 Health Oracle with x402 Micropayments

## One-liner
AI agents check L2 network health before sending transactions — kernel-level telemetry via eBPF, paid through x402 on Base and Hedera.

## Description (for submission form)

Phoenix Zero is a production L2 health oracle that gives AI agents nanosecond-precision network telemetry before they commit funds on-chain. Unlike Chainlink's binary up/down sequencer feed (30s OCR updates), Phoenix measures P99 RTT, packet loss, revert ratios, and stall detection across 12 L2 networks every 2 seconds using eBPF XDP at the kernel level.

**What's new during ETHOnline (Sep 4-13, 2026):**
- 4-channel AI agent distribution system (MCP Registry, Olas Mech tool, Docker, RPC Gateway)
- MCP Server published to npm (`phoenix-mcp-server`) and MCP Registry for AI assistant discovery
- RPC Gateway deployed — transparent proxy that health-checks before forwarding eth_sendRawTransaction
- Docker support for one-command deployment
- Olas Mech tool interface for DeFi agent marketplace

**Pre-existing (built since March 2026):**
- eBPF XDP threat filter (live since Aug 28, prog 5437)
- x402 payment gateway — dual facilitator: CDP (Base USDC) + Blocky402 (Hedera HBAR)
- 12-chain multi-chain probe with 2s sampling
- BLAKE3 + Ed25519 integrity signing
- 14-layer Silicon DNA bot detection (ML-KEM-768, Argon2 PoW, Spearman correlation)
- Isolation Forest anomaly scoring
- First revenue: $0.02 USDC on Base (Sep 1)

**Tech stack:** TypeScript, Python/FastAPI, eBPF/XDP, x402, MCP SDK, Docker

**Live:** https://rtt.phoenix-ai.work
**npm:** phoenix-mcp-server
**GitHub:** https://github.com/kant19801201behax5/x402-health-oracle

## Partner Prize Explanations

### 1. Hedera — AI & Agentic Payments ($6K)
Phoenix Zero integrates Hedera via Blocky402 facilitator for x402 micropayments. AI agents querying network health can pay with HBAR on Hedera testnet. The x402 gateway handles payment verification, and the agent receives kernel-level telemetry (RTT, packet loss, anomaly scores) in response. First Hedera payment of 0.01 HBAR was settled Sep 5. The integration demonstrates a real agentic payment flow: agent needs data → 402 challenge → agent pays HBAR → agent receives health verdict → agent decides whether to transact on L2.

### 2. Arc (Circle) — Best Agentic Economy (Continuity) ($1,666)
Phoenix Zero's primary payment rail is USDC on Base via Coinbase CDP facilitator. Two on-chain settlements totaling $0.02 USDC prove the agentic economy flow works: AI agents autonomously pay for network intelligence that protects their transactions. The x402 protocol (HTTP 402 Payment Required) is the native payment standard — no wallet UI, no approval popups, just machine-to-machine micropayments. The 4-channel distribution (MCP, RPC Gateway, Direct HTTP, Olas) ensures agents find and pay us through whatever interface they use.

### 3. Bazantic — Help an Agent Use Your Project (Continuity) ($1K)
We published `phoenix-mcp-server` to npm and the MCP Registry as `io.github.kant19801201behax5/phoenix-mcp-server`. The MCP tool `preflight_network_health` lets any AI coding assistant (Claude, Cursor, Windsurf) discover and use our health oracle semantically. When an agent asks "is Base safe for a transaction?", it finds our tool in the registry, calls it, and gets a PASS/DEGRADED/FAIL verdict with kernel-level evidence. This is literally "help an agent use your project" — zero configuration, pure discovery.

---

## Video Script (2:30 target — Kent reads/adapts this)

### 0:00-0:15 — Intro
"Hi, I'm Kent. Phoenix Zero is a kernel-level L2 health oracle. AI agents check network health before sending transactions — and pay with x402 micropayments on Base and Hedera."

### 0:15-0:40 — Problem
"When Base went down for 2 hours in June 2026, $10.95 billion was at risk. 64% of DeFi protocols don't check sequencer health. Chainlink gives binary up/down with 30-second updates. Agents need real-time, nanosecond-precision data — BEFORE signing."
[SHOW: slide with Base outage stats]

### 0:40-1:10 — Solution / Architecture
"Phoenix Zero runs eBPF XDP at the kernel level on our server. It measures RTT, packet loss, and anomalies across 12 L2 chains every 2 seconds. Agents access it through 4 channels."
[SHOW: architecture diagram from README — MCP / Olas / Direct x402 / RPC Gateway]

### 1:10-1:40 — Live Demo: RPC Gateway
[SHOW terminal — run these commands:]
```
curl -X POST https://rtt.phoenix-ai.work/rpc/base \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```
"Here I send a normal RPC request to Base through our gateway. It returns the block number AND an X-Phoenix-Health: PASS header. If I tried eth_sendRawTransaction during a network failure, it would return 503 — blocking the transaction to protect funds."

### 1:40-2:00 — Live Demo: x402 Payment
[SHOW terminal:]
```
curl -i https://rtt.phoenix-ai.work/api/v1/health
```
"The premium endpoint returns 402 Payment Required with an x402 challenge. An agent pays $0.01 USDC on Base or HBAR on Hedera — and gets full 12-chain telemetry with cryptographic integrity."

### 2:00-2:20 — What's New During ETHOnline
"During ETHOnline I built the 4-channel distribution: published an MCP Server to npm and the MCP Registry, deployed the RPC Gateway to production, created Docker support, and built an Olas Mech tool. The core oracle has been running in production since March."
[SHOW: npm package page, MCP Registry]

### 2:20-2:30 — Close
"Phoenix Zero. Kernel-level intelligence. x402 micropayments. 12 chains. 620 tests. Live in production. Thank you."

---

## Pre-recording Checklist
- [ ] Screen recording software (OBS Studio — free, 720p+)
- [ ] Quiet room, no echo
- [ ] Terminal open with commands ready to paste
- [ ] Browser tabs: npm package page, rtt.phoenix-ai.work dashboard
- [ ] Architecture diagram slide ready
- [ ] Speak slowly and clearly
- [ ] Total time: 2:00-2:30 (leave buffer under 4:00 limit)
