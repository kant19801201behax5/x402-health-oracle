# Autonomous Security Infrastructure

## The Problem

AI agents are entering the blockchain economy. They trade, bridge, and execute across L2 chains — but they have no way to verify whether the infrastructure they depend on is safe. Meanwhile, the infrastructure has no way to distinguish a legitimate agent from a malicious bot at the kernel level.

## What We Built

**x402 Health Oracle** — a real-time sequencer health service that AI agents pay to query, protected by kernel-level security.

Three layers, each deployed:

### 1. XDP Shield (Kernel-Speed Threat Response)
- eBPF XDP program on eth0 drops packets from banned IPs **before the TCP stack** (~5-20µs)
- Silicon DNA's 14-layer bot detection feeds banned IPs into the BPF map every 5 seconds
- Result: attack traffic never reaches userspace

**Status:** Live on production since Aug 28, 2026

### 2. LSM Agent Guard (OS-Level AI Agent Sandboxing)
- BPF LSM hooks restrict what an autonomous AI agent process can do at the kernel level
- Blocks `execve` (no spawning new processes)
- Restricts network connections to ports 443 and 8545 only (HTTPS + Ethereum RPC)
- Policy loaded per-PID from userspace

**Status:** Compiled, requires kernel boot parameter (`lsm=...,bpf`)

### 3. ZK Health Proofs (Privacy-Preserving Performance Attestation)
- Phase 0 (live): HMAC-SHA256 commitment proving node health without revealing raw metrics
- Phase 1 (design): risc0 zkVM circuit for trustless verification
- Phase 2 (concept): On-chain Solidity verifier on Base

**Status:** Phase 0 deployed at `/api/health-proof`

## Revenue Model

**x402 micropayments:** Every API query costs $0.01 USDC on Base. No subscriptions, no API keys for basic access — pure per-query monetization via the x402 HTTP 402 protocol.

- 7 paid endpoints (health, safe, price, chains, classify, health-proof)
- Coinbase CDP facilitator verifies payment on-chain
- First revenue: $0.02 USDC (Sep 1, 2026)

**Unit economics at scale:**
| Queries/day | Daily Revenue | Annual Revenue |
|-------------|---------------|----------------|
| 1,000 | $10 | $3,650 |
| 10,000 | $100 | $36,500 |
| 100,000 | $1,000 | $365,000 |
| 1,000,000 | $10,000 | $3,650,000 |

## Technical Moat

| Layer | Technology | Competitors |
|-------|-----------|-------------|
| L0: Physical | CPU jitter fingerprinting (eBPF kprobe) | None |
| L1: Hardware | GPU/UA consistency check | Basic |
| L2: TLS | JA4 fingerprint risk scoring | Cloudflare |
| L3: Behavioral | Spearman rank correlation (micro-stall) | None |
| L4: Statistical | Drift-adaptive σ² threshold (P²-quantile) | None |
| L5: Cryptographic | Argon2id PoW with ASIC-spoof detection | None |
| L6: Information | Shannon entropy + autocorrelation | Basic |
| L7: PQC | ML-KEM-768 (NIST FIPS 203) per-session | None |

**14 detection layers**, from kernel (eBPF) to application (Privacy Pass tokens). No existing WAF or bot detection operates at the physical measurement layer.

## Ecosystem Fit

- **EigenLayer AVS:** health proofs as operator validation
- **Chainlink DON:** cross-oracle health data feed
- **DePIN:** node uptime verification for reward distribution
- **x402 ecosystem:** reference implementation for AI-agent commerce

## The Team

Solo developer. Everything from kernel eBPF to x402 payment integration built and deployed by one person.

## Paper

"Silicon DNA: The Physics of Network Identity Verification"
DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862)

## Links

- **Live API:** https://rtt.phoenix-ai.work/api/v1/health (402 — pay $0.01 USDC)
- **Discovery:** https://rtt.phoenix-ai.work/.well-known/x402
- **Free health:** https://rtt.phoenix-ai.work/api/health
- **GitHub:** https://github.com/kant19801201behax5/x402-health-oracle
