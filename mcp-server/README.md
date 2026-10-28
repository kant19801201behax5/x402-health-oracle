# Phoenix Zero MCP Server

Model Context Protocol server that gives AI agents a PASS/FAIL answer for an L2 before they send a transaction.

The free answer is delayed ~60 s and does not include the revert ratio. The live verdict, with the revert ratio for Base and Arbitrum, is paid via x402 (the 402 offers USDC on Base, Polygon or Arbitrum).

## Tools

### `check_safety_free`

The raw answer of the free endpoint `/api/v1/demo/safe`: `safe` true/false plus a `reason` code (`safe` is null only with `warming_up`) for the chosen chain. Delayed ~60 s. Limit: 100 requests per IP per day.

**Parameters:**
- `chain` (optional, default `base`) — one of: base, arbitrum, optimism, zksync, scroll, mantle, linea, blast, mode, taiko, polygon_zkevm, casper (L1 reference, not an L2)

### `preflight_network_health`

Decide whether an L2 is suitable for sending a transaction: PASS or FAIL with a reason code for the chosen chain.

**Parameters:**
- `chain` (optional, default `base`) — one of: base, arbitrum, optimism, zksync, scroll, mantle, linea, blast, mode, taiko, polygon_zkevm, casper (L1 reference, not an L2)
- `metric` — `health_check` (free, delayed, no revert ratio) | `latency` (x402, from $0.01) | `revert_ratio` (x402, from $0.01; Base and Arbitrum only, null for other chains)

**Returns for `health_check`:** `PASS` or `FAIL` plus a `reason`, `delayed_s`, `as_of` and a link to the live verdict (`GET /api/v1/safe`, x402). The `reason` is one of seven codes:
- `ok` — no chain halt, sequencer stall or high latency in the delayed snapshot (PASS). The free check has no revert ratio and no elevated-latency tier, so the paid /api/v1/safe can still answer `elevated_latency`, `elevated_revert` or `high_revert`.
- `no_data` — no measurements for the chain (FAIL)
- `data_stale` — the latest measurement is older than 30 s (FAIL)
- `chain_halted` — the head block is older than 600 s (EVM chains; not evaluated for casper) (FAIL)
- `sequencer_stall` — the probe's stall flag is set, or p99 ≥ 5000 ms (casper 10000 ms) (FAIL)
- `high_latency` — p99 above 500 ms (casper 2000 ms) (FAIL)
- `warming_up` — no snapshot older than 60 s yet, e.g. right after a gateway restart; `safe` is null (FAIL)

The free verdict does not include the revert ratio. The revert ratio (Base and Arbitrum) and the reason codes `elevated_revert`, `high_revert`, `elevated_latency` come only from the paid `/api/v1/safe`.

**Returns for `latency` and `revert_ratio`:** the free PASS/FAIL fields above plus the payment terms (`requires_payment`, `price`, `endpoint`, `payment_protocol`, `payment_rails`). The live values come from the paid x402 endpoint; this server does not pay on your behalf.

## Setup

```bash
npm install
npm run build
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "phoenix-zero": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-server/dist/index.js"]
    }
  }
}
```

### Test with Inspector

```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

## Data Source

Live production oracle at `rtt.phoenix-ai.work`:
- 12 chains polled every ~2 s, 2-3 independent RPC nodes per chain (Casper 10)
- eBPF (uprobes on `SSL_write`/`SSL_read`) also measures kernel-level TLS wait to the HTTPS RPC nodes; it is returned as `kernel_tls_rtt` (p50/p95 over 60 s) in the paid /api/v1/health and /api/v1/safe and is not used in the verdict
- BLAKE3 + Ed25519 signed feed records; API responses are signed EIP-191 (`signature`, `signer`)
- x402 micropayment for the live verdict and live values: normally $0.01 USDC per query, up to $0.10 when Base is under stress; the current price is in the PAYMENT-REQUIRED header and at GET /api/v1/price
- polygon_zkevm: sunset by Polygon Labs on 1 Jul 2026 — the oracle answers FAIL chain_halted

## License

MIT
