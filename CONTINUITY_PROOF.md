# Continuity Proof

This project extends [SiliconDNA-PhoenixZero](https://github.com/kant19801201behax5/SiliconDNA-PhoenixZero), developed since March 2026.

## Pre-existing work (before Sep 4, 2026)

| Component | Status | Evidence |
|-----------|--------|----------|
| 12-chain RPC probe (2s polling) | Live since Mar 2026 | 71K+ feed.jsonl records |
| BLAKE3 + Ed25519 telemetry signing | Deployed | `phoenix_integrity.py` |
| 14-layer bot detection (Silicon DNA) | Deployed | `server.ts` — Spearman, Argon2, jitter, PQC |
| ML-KEM-768 post-quantum key exchange | Deployed | Per-WebSocket session handshake |
| Isolation Forest anomaly scoring | Deployed | numpy-only, no sklearn |
| x402 gateway (Base USDC, CDP facilitator) | Live, 2 settlements | $0.02 USDC revenue (Sep 1) |
| eBPF XDP threat filter | Live since Aug 28 | `ip link show eth0` → xdpgeneric, prog id 5437 |
| eBPF LSM agent guard | Compiled | Requires kernel boot param `lsm=...,bpf` |
| Zenodo paper | Published Sep 2 | DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862) |
| Casper Agentic Buildathon | Finalist | ETHGlobal history |

## Built for ETHOnline 2026 (Sep 4-16)

| Feature | Description |
|---------|-------------|
| **Blocky402 Hedera integration** | x402 payment rail on Hedera testnet via Blocky402 facilitator, alongside existing Base mainnet |
| **eBPF LSM as Agentic IAM** | Dynamic task-scoped kernel sandbox for AI agent processes — blocks execve, restricts network to ports 443/8545 |
| **Recommendation engine fix** | Per-chain-type thresholds (L1 vs L2) for accurate health recommendations |
| **Security hardening** | eBPF detection via `ip link` (non-root safe), classifier uses server-side metrics only |
| **Complete source release** | All 17 TypeScript service modules, TypeScript compiles with 0 errors |
| **Multi-facilitator architecture** | CDP (Base mainnet) + Blocky402 (Hedera testnet) coexist in single gateway |

## Repository mapping

- **This repo** (`x402-health-oracle`): hackathon submission, public, no internal references
- **Parent repo** (`SiliconDNA-PhoenixZero`): ongoing development, full history
- **Production**: `rtt.phoenix-ai.work` — live API serving real traffic since March 2026
