import { describe, it, expect, vi, beforeEach } from "vitest";

const CHAINS = [
  "base", "arbitrum", "optimism", "zksync", "scroll",
  "mantle", "linea", "blast", "mode", "taiko",
  "polygon_zkevm", "casper",
];

function deriveVerdict(data: {
  health: string;
  safe: boolean;
  last_measurement_s: number;
}) {
  if (data.health !== "operational") {
    return { verdict: "FAIL", reason: `service ${data.health}` };
  }
  if (data.last_measurement_s > 30) {
    return {
      verdict: "DEGRADED",
      reason: `stale data: last measurement ${data.last_measurement_s}s ago`,
    };
  }
  if (!data.safe) {
    return { verdict: "FAIL", reason: "unsafe conditions detected by kernel telemetry" };
  }
  return { verdict: "PASS", reason: "operational, data fresh, safe to execute" };
}

describe("deriveVerdict", () => {
  it("returns PASS for healthy operational state", () => {
    const result = deriveVerdict({
      health: "operational",
      safe: true,
      last_measurement_s: 0,
    });
    expect(result.verdict).toBe("PASS");
  });

  it("returns FAIL when health is not operational", () => {
    const result = deriveVerdict({
      health: "degraded",
      safe: true,
      last_measurement_s: 0,
    });
    expect(result.verdict).toBe("FAIL");
    expect(result.reason).toContain("degraded");
  });

  it("returns DEGRADED when data is stale (>30s)", () => {
    const result = deriveVerdict({
      health: "operational",
      safe: true,
      last_measurement_s: 45,
    });
    expect(result.verdict).toBe("DEGRADED");
    expect(result.reason).toContain("stale");
  });

  it("returns FAIL when safe is false", () => {
    const result = deriveVerdict({
      health: "operational",
      safe: false,
      last_measurement_s: 2,
    });
    expect(result.verdict).toBe("FAIL");
    expect(result.reason).toContain("unsafe");
  });

  it("prioritizes health check over staleness", () => {
    const result = deriveVerdict({
      health: "down",
      safe: true,
      last_measurement_s: 999,
    });
    expect(result.verdict).toBe("FAIL");
    expect(result.reason).toContain("down");
  });

  it("prioritizes staleness over safe flag", () => {
    const result = deriveVerdict({
      health: "operational",
      safe: false,
      last_measurement_s: 60,
    });
    expect(result.verdict).toBe("DEGRADED");
    expect(result.reason).toContain("stale");
  });
});

describe("chains", () => {
  it("has exactly 12 chains", () => {
    expect(CHAINS).toHaveLength(12);
  });

  it("includes all expected L2 networks", () => {
    expect(CHAINS).toContain("base");
    expect(CHAINS).toContain("arbitrum");
    expect(CHAINS).toContain("optimism");
    expect(CHAINS).toContain("zksync");
    expect(CHAINS).toContain("casper");
  });

  it("has no duplicates", () => {
    const unique = new Set(CHAINS);
    expect(unique.size).toBe(CHAINS.length);
  });
});

describe("server.json manifest", () => {
  it("is valid JSON with required fields", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const manifestPath = path.resolve(import.meta.dirname, "..", "server.json");
    const raw = fs.readFileSync(manifestPath, "utf-8");
    const manifest = JSON.parse(raw);

    expect(manifest.name).toBe("io.github.kant19801201behax5/phoenix-mcp-server");
    expect(manifest.tools).toHaveLength(1);
    expect(manifest.tools[0].name).toBe("preflight_network_health");
    expect(manifest.version).toBe("1.0.1");
    expect(manifest.repository.url).toContain("x402-health-oracle");
  });
});
