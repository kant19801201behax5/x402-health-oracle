#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const PHOENIX_BASE = process.env.PHOENIX_API_URL ?? "https://rtt.phoenix-ai.work";

const CHAINS = [
  "base", "arbitrum", "optimism", "zksync", "scroll",
  "mantle", "linea", "blast", "mode", "taiko",
  "polygon_zkevm", "casper",
] as const;

type Chain = (typeof CHAINS)[number];

interface HealthResponse {
  health: string;
  safe: boolean;
  mode: string;
  uptime_s: number;
  last_measurement_s: number;
  version: string;
}

type Verdict = "PASS" | "DEGRADED" | "FAIL";

function deriveVerdict(data: HealthResponse): {
  verdict: Verdict;
  reason: string;
} {
  if (data.health !== "operational") {
    return { verdict: "FAIL", reason: `service ${data.health}` };
  }
  if (data.last_measurement_s > 30) {
    return { verdict: "DEGRADED", reason: `stale data: last measurement ${data.last_measurement_s}s ago` };
  }
  if (!data.safe) {
    return { verdict: "FAIL", reason: "unsafe conditions detected by kernel telemetry" };
  }
  return { verdict: "PASS", reason: "operational, data fresh, safe to execute" };
}

async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${PHOENIX_BASE}/api/health`);
  if (!res.ok) {
    throw new Error(`Phoenix API returned ${res.status}`);
  }
  return res.json() as Promise<HealthResponse>;
}

async function fetchChainHealth(chain: Chain): Promise<Record<string, unknown> | null> {
  const res = await fetch(`${PHOENIX_BASE}/api/v1/chains/${chain}`);
  if (res.status === 402) return null;
  if (!res.ok) return null;
  return res.json() as Promise<Record<string, unknown>>;
}

const server = new McpServer({
  name: "phoenix-zero",
  version: "1.0.0",
});

server.tool(
  "preflight_network_health",
  `Determine whether an L2 network is currently suitable for transaction execution using kernel-level network telemetry. Returns PASS, DEGRADED, or FAIL with RTT, packet-loss and timestamp evidence. Covers 12 L2 chains (Base, Arbitrum, Optimism, zkSync, Scroll, Mantle, Linea, Blast, Mode, Taiko, Polygon zkEVM, Casper). Data sourced from eBPF XDP probes with 2-second sampling interval, signed with BLAKE3+Ed25519.`,
  {
    chain: z
      .enum(CHAINS)
      .optional()
      .describe("L2 chain to check. Omit for aggregate health across all 12 chains."),
    metric: z
      .enum(["health_check", "rtt_ns", "revert_ratio"])
      .default("health_check")
      .describe(
        "health_check = PASS/DEGRADED/FAIL verdict (free). rtt_ns = nanosecond RTT (x402 $0.01). revert_ratio = transaction revert rate (x402 $0.01)."
      ),
  },
  async ({ chain, metric }) => {
    try {
      const health = await fetchHealth();
      const { verdict, reason } = deriveVerdict(health);

      if (metric === "health_check") {
        const result: Record<string, unknown> = {
          verdict,
          reason,
          oracle_uptime_s: health.uptime_s,
          last_measurement_s: health.last_measurement_s,
          chains_monitored: CHAINS.length,
          source: "rtt.phoenix-ai.work",
          integrity: "BLAKE3+Ed25519 on every measurement",
          sampling_interval: "2s",
        };

        if (chain) {
          result.chain = chain;
          const chainData = await fetchChainHealth(chain);
          if (chainData) {
            result.chain_data = chainData;
          } else {
            result.chain_detail = `Per-chain telemetry for ${chain} requires x402 payment ($0.01). Call: GET ${PHOENIX_BASE}/api/v1/chains/${chain}`;
          }
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      const premiumEndpoint =
        metric === "rtt_ns"
          ? `${PHOENIX_BASE}/api/v1/health`
          : `${PHOENIX_BASE}/api/v1/safe`;

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                verdict,
                reason,
                metric_requested: metric,
                requires_payment: true,
                price: "$0.01 USDC",
                payment_protocol: "x402 (HTTP 402 micropayment)",
                endpoint: premiumEndpoint,
                payment_rails: [
                  { network: "Base mainnet (eip155:8453)", asset: "USDC" },
                  { network: "Hedera testnet", asset: "native HBAR" },
                ],
                how_to_pay:
                  "Send GET request to the endpoint. Server returns 402 with X-PAYMENT header containing payment challenge. Complete x402 payment flow to receive full telemetry.",
                discovery: `${PHOENIX_BASE}/.well-known/x402`,
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                verdict: "FAIL",
                reason: `oracle unreachable: ${message}`,
                source: PHOENIX_BASE,
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
