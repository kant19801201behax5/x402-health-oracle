# Phoenix Zero MCP Server

Model Context Protocol server exposing L2 network health telemetry to AI agents.

## Tool: `preflight_network_health`

Determine whether an L2 network is currently suitable for transaction execution using kernel-level network telemetry.

**Parameters:**
- `chain` (optional) — one of: base, arbitrum, optimism, zksync, scroll, mantle, linea, blast, mode, taiko, polygon_zkevm, casper
- `metric` — `health_check` (free) | `rtt_ns` (x402 $0.01) | `revert_ratio` (x402 $0.01)

**Returns:** `PASS`, `DEGRADED`, or `FAIL` with evidence (uptime, staleness, sampling interval).

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
- 12 L2 chains monitored every 2 seconds
- eBPF XDP kernel-level probes
- BLAKE3 + Ed25519 integrity on every measurement
- x402 micropayment for premium data ($0.01/query)

## License

MIT
