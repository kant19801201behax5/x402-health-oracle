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
| eBPF XDP threat filter | Live since Aug 28 | `ip link show eth0` → xdpgeneric, prog id 6293 |
| eBPF LSM agent guard | **PRODUCTION** since Sep 8 | prog 59, kernel boot `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` |
| Zenodo paper | Published Sep 2 | DOI: [10.5281/zenodo.22239862](https://doi.org/10.5281/zenodo.22239862) |
| Casper Agentic Buildathon | Finalist | ETHGlobal history |

## Built for ETHOnline 2026 (Sep 4-13)

| Feature | Description |
|---------|-------------|
| **MCP Server → npm + Registry** | `phoenix-mcp-server@1.1.0` published to npm (2 tools: `check_safety_free` + `preflight_network_health`); listed on MCP Registry |
| **RPC Gateway** | FastAPI proxy on port 3003 — health-checks before forwarding `eth_sendRawTransaction` to 11 upstream L2 RPCs. Live at `rtt.phoenix-ai.work/rpc/` |
| **Docker support** | `docker-compose.yml` — one-command deployment of gateway + probe |
| **Olas Mech tool** | `phoenix_health_check.py` — tool interface for DeFi agent marketplace (on-chain registration pending) |
| **Blocky402 Hedera integration** | x402 payment rail on Hedera testnet via Blocky402 facilitator, alongside existing Base mainnet |
| **eBPF LSM as Agentic IAM** | Dynamic task-scoped kernel sandbox for AI agent processes — blocks execve, restricts network to ports 443/8545 |
| **Recommendation engine fix** | Per-chain-type thresholds (L1 vs L2) for accurate health recommendations |
| **Security hardening** | eBPF detection via `ip link` (non-root safe), classifier uses server-side metrics only |
| **Complete source release** | All 17 TypeScript service modules, TypeScript compiles with 0 errors |
| **Multi-facilitator architecture** | CDP (Base mainnet) + Blocky402 (Hedera testnet) coexist in single gateway |

## Repository mapping

- **This repo** (`x402-health-oracle`): hackathon submission, public, no internal references
- **Parent repo** (`SiliconDNA-PhoenixZero`): ongoing development, full history
| **Free Demo Endpoint** | `GET /api/v1/demo/safe` — 100 calls/IP/day, no payment. All 12 chains. |
| **MCP Discovery** | `/.well-known/mcp.json` — 5 tools for LLM agent auto-discovery |
| **x402 Discovery** | `/.well-known/x402` — 8 paid + 5 free endpoints, fixed Sep 16 (was missing preflight + correlation) |
| **Surge Pricing** | 3-tier dynamic: $0.01 normal / $0.03 elevated / $0.10 storm. 10s update interval |

## Repository mapping

- **This repo** (`x402-health-oracle`): hackathon submission, public, no internal references
- **Parent repo** (`SiliconDNA-PhoenixZero`): ongoing development, full history
- **Production**: `rtt.phoenix-ai.work` — live API serving real traffic since March 2026, 13 systemd services, 170+ days uptime
