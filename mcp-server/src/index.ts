#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const PHOENIX_BASE = process.env.PHOENIX_API_URL ?? "https://rtt.phoenix-ai.work";

export const CHAINS = [
  "base", "arbitrum", "optimism", "zksync", "scroll",
  "mantle", "linea", "blast", "mode", "taiko",
  "polygon_zkevm", "casper",
] as const;

type Chain = (typeof CHAINS)[number];

type Verdict = "PASS" | "DEGRADED" | "FAIL";

// Verdict for ONE chain, derived from that chain's own safe/reason (oracle /v1/demo/safe).
// 1.2.x derived it from /api/health (this node's liveness), which said PASS for any chain
// whenever the server was up — fixed in 1.3.0.
export function verdictFromChain(safe: unknown, reason: unknown): { verdict: Verdict; reason: string } {
  const r = typeof reason === "string" ? reason : "unknown";
  if (safe === true) return { verdict: "PASS", reason: r };
  if (r === "elevated_latency" || r === "elevated_revert") return { verdict: "DEGRADED", reason: r };
  return { verdict: "FAIL", reason: r }; // high_latency, high_revert, sequencer_stall, data_stale, warming_up, unknown
}

async function fetchDemoSafe(chain: Chain): Promise<Record<string, unknown>> {
  const res = await fetch(`${PHOENIX_BASE}/api/v1/demo/safe?chain=${chain}`);
  if (!res.ok) {
    throw new Error(`Demo endpoint returned ${res.status}`);
  }
  return res.json() as Promise<Record<string, unknown>>;
}

const PAYMENT_RAILS = [
  { network: "Base (eip155:8453)", asset: "USDC" },
  { network: "Polygon (eip155:137)", asset: "USDC" },
  { network: "Arbitrum One (eip155:42161)", asset: "USDC" },
];

const text = (obj: unknown, isError = false) => ({
  content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }],
  ...(isError ? { isError: true } : {}),
});

export const server = new McpServer({
  name: "phoenix-zero",
  version: "1.3.0",
});

server.registerTool(
  "check_safety_free",
  {
    description:
      "FREE safety check for an L2 before sending a transaction (100 calls/IP/day). Returns safe/unsafe with a reason code for the chosen chain. The verdict is delayed ~60 s; the live verdict is the paid x402 endpoint GET /api/v1/safe ($0.01 USDC).",
    inputSchema: {
      chain: z.enum(CHAINS).optional().describe("L2 chain to check. Defaults to base."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ chain }) => {
    try {
      return text(await fetchDemoSafe(chain ?? "base"));
    } catch (err) {
      return text({ error: err instanceof Error ? err.message : String(err), source: PHOENIX_BASE }, true);
    }
  }
);

server.registerTool(
  "preflight_network_health",
  {
    description:
      "Decide whether an L2 is suitable for transaction execution right now: PASS / DEGRADED / FAIL for the chosen chain, from Phoenix Zero measurements (each chain polled every ~2 s against 2-3 independent RPC nodes; revert ratio for Base/Arbitrum; records signed BLAKE3+Ed25519). The free answer is delayed ~60 s; live data (p99 latency, revert ratio) is paid via x402 ($0.01 USDC on Base, Polygon or Arbitrum).",
    inputSchema: {
      chain: z.enum(CHAINS).optional().describe("L2 chain to check. Defaults to base."),
      metric: z
        .enum(["health_check", "latency", "revert_ratio"])
        .default("health_check")
        .describe("health_check = free delayed PASS/DEGRADED/FAIL. latency / revert_ratio = live values via paid x402 endpoints."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async ({ chain, metric }) => {
    const c: Chain = chain ?? "base";
    try {
      const demo = await fetchDemoSafe(c);
      const { verdict, reason } = verdictFromChain(demo.safe, demo.reason);
      const base = {
        chain: c,
        verdict,
        reason,
        delayed_s: demo.delayed_s ?? null,
        as_of: demo.as_of ?? null,
        source: "rtt.phoenix-ai.work",
      };
      if (metric === "health_check") {
        return text({ ...base, live_verdict: `GET ${PHOENIX_BASE}/api/v1/safe?chain=${c} (x402, $0.01 USDC)` });
      }
      return text({
        ...base,
        metric_requested: metric,
        requires_payment: true,
        price: "$0.01 USDC",
        endpoint: metric === "latency" ? `${PHOENIX_BASE}/api/v1/chains/${c}` : `${PHOENIX_BASE}/api/v1/safe?chain=${c}`,
        payment_protocol: "x402 v2 (HTTP 402; terms in the PAYMENT-REQUIRED header and the response body)",
        payment_rails: PAYMENT_RAILS,
      });
    } catch (err) {
      return text({ error: err instanceof Error ? err.message : String(err), source: PHOENIX_BASE }, true);
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (!process.env.VITEST) {
  main().catch((err) => {
    console.error("Fatal:", err);
    process.exit(1);
  });
}
