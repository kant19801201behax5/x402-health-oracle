# x402 Health Oracle

**Real-time L2 sequencer health data, monetized via x402 micropayments.**

Live at: `https://rtt.phoenix-ai.work/api/v1/health`

## What it does

AI agents pay $0.01 USDC on Base per query to get real-time health metrics across 12 L2 chains (Base, Arbitrum, Optimism, zkSync, Blast, Linea, Mantle, Mode, Scroll, Taiko, Polygon zkEVM, Casper). The oracle measures P99/P95 latency, revert ratios, gas pressure, and stall detection — then returns an execution recommendation (SAFE / ELEVATED / HIGH_RISK / STALL).

## How it works

```
Agent → GET /api/v1/health
     ← 402 Payment Required (x402 challenge)
Agent → pays $0.01 USDC on Base via x402
     ← 200 OK + real-time chain health data
```

**Payment flow:** The x402 protocol (HTTP 402) gates API access behind on-chain micropayments. The Coinbase CDP facilitator verifies payment on Base mainnet before releasing data.

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│  multi_chain_probe   │────▶│   wss_distributor     │────▶│  x402_gateway    │
│  12 chains, 2s poll  │     │  BLAKE3+Ed25519 sign  │     │  FastAPI :3002   │
│  eth_blockNumber     │     │  Isolation Forest      │     │  $0.01/query     │
│  eth_getBlockReceipts│     │  anomaly scoring       │     │  7 paid endpoints│
└─────────────────────┘     └──────────────────────┘     └──────────────────┘
                                                              │
                                                              ▼
                                                    ┌──────────────────┐
                                                    │   server.ts       │
                                                    │  Silicon DNA      │
                                                    │  14-layer bot     │
                                                    │  detection :3001  │
                                                    └──────────────────┘
```

### Components

| Component | File | Description |
|-----------|------|-------------|
| **x402 Gateway** | `gateway/x402_gateway.py` | FastAPI payment gateway with 7 x402-gated endpoints |
| **Multi-Chain Probe** | `probe/multi_chain_probe.py` | 12-chain RPC poller (eth_blockNumber every 2s, revert analysis) |
| **WSS Distributor** | `probe/wss_distributor.py` | WebSocket broadcast with BLAKE3+Ed25519 integrity signing |
| **Silicon DNA** | `gateway/server.ts` | 14-layer anti-bot system (ML-KEM-768 PQC, Argon2 PoW, Spearman correlation) |
| **Access Gate** | `gateway/access_gate.py` | API key management with Supabase sync |
| **Integrity** | `gateway/phoenix_integrity.py` | Ed25519 provenance signing for all telemetry |

## x402 Endpoints

All endpoints cost $0.01 USDC on Base (chain ID 8453).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Full health snapshot (all 12 chains) |
| `/api/v1/safe` | GET | Boolean: safe to execute? |
| `/api/v1/price` | GET | Current pricing with MEV surge multiplier |
| `/api/v1/chains/{chain}` | GET | Single-chain health |
| `/api/v1/classify` | POST | Agent classification (HUMAN/LEGIT_AGENT/MALICIOUS_BOT) |
| `/api/v1/health-proof` | GET | ZK-lite verifiable proof of node health |

## Verified Settlements

Two on-chain settlements on Base mainnet (Sep 1, 2026):
- **$0.01 USDC** — first x402 payment verified
- **$0.01 USDC** — second settlement confirmed
- **Total revenue: $0.02 USDC**

PAY_TO: `0xbb967F16C7f3e9B4c1626680684445d41dBE44Ab`

## Security

- **ML-KEM-768** (NIST FIPS 203) post-quantum key exchange per WebSocket connection
- **BLAKE3 + Ed25519** integrity signing on all telemetry
- **14-layer bot detection**: CPU jitter, Spearman correlation, Argon2 PoW, Frankenstein header analysis, Sybil clustering, Privacy Pass tokens, drift-adaptive thresholds
- **Isolation Forest** anomaly scoring (numpy-only, no sklearn dependency)

## Tech Stack

- Python 3.10 (FastAPI/uvicorn for x402 gateway, asyncio probes)
- Node.js/TypeScript (Silicon DNA anti-bot, Express + WS)
- Coinbase CDP x402 facilitator
- Base mainnet (USDC ERC-20)
- DigitalOcean VPS behind Cloudflare

## Paper

Silicon DNA: The Physics of Network Identity Verification
DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862)

## License

MIT
