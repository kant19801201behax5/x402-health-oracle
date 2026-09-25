import { describe, it, expect } from "vitest";
import { CHAINS, verdictFromChain, server } from "../src/index";

// Tests exercise the REAL server code (earlier versions tested a local copy of old logic,
// which is how a verdict derived from node liveness instead of the chain went unnoticed).

describe("verdictFromChain — verdict comes from the chosen chain's own state", () => {
  it("PASS when the chain is safe", () => {
    expect(verdictFromChain(true, "ok")).toEqual({ verdict: "PASS", reason: "ok" });
  });
  it("DEGRADED on elevated latency or revert", () => {
    expect(verdictFromChain(false, "elevated_latency").verdict).toBe("DEGRADED");
    expect(verdictFromChain(false, "elevated_revert").verdict).toBe("DEGRADED");
  });
  it("FAIL on high latency, high revert, stall, stale or warm-up", () => {
    for (const r of ["high_latency", "high_revert", "sequencer_stall", "data_stale", "warming_up"]) {
      expect(verdictFromChain(false, r).verdict).toBe("FAIL");
    }
  });
  it("never PASS when safe is missing or not a boolean true", () => {
    expect(verdictFromChain(undefined, undefined).verdict).toBe("FAIL");
    expect(verdictFromChain(null, "ok").verdict).toBe("FAIL");
    expect(verdictFromChain("true", "ok").verdict).toBe("FAIL");
  });
});

describe("chains", () => {
  it("has exactly 12 unique chains incl. the main L2s", () => {
    expect(CHAINS).toHaveLength(12);
    expect(new Set(CHAINS).size).toBe(12);
    for (const c of ["base", "arbitrum", "optimism", "zksync", "casper"]) expect(CHAINS).toContain(c);
  });
});

describe("registered tools (real server instance)", () => {
  const tools = (server as any)._registeredTools as Record<string, any>;
  it("registers exactly the two tools with input schemas", () => {
    expect(Object.keys(tools).sort()).toEqual(["check_safety_free", "preflight_network_health"]);
    for (const name of Object.keys(tools)) expect(tools[name].inputSchema).toBeDefined();
  });
  it("tools are read-only", () => {
    for (const name of Object.keys(tools)) {
      expect(tools[name].annotations.readOnlyHint).toBe(true);
      expect(tools[name].annotations.destructiveHint).toBe(false);
    }
  });
  it("descriptions make no claims we do not measure", () => {
    for (const name of Object.keys(tools)) {
      const d: string = tools[name].description;
      expect(d).not.toMatch(/packet[- ]loss|XDP|nanosecond|\$5-\$15/i);
    }
  });
});

describe("server.json manifest", () => {
  it("matches the code: name, version, tools, read-only", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const manifest = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "..", "server.json"), "utf-8"));
    expect(manifest.name).toBe("io.github.kant19801201behax5/phoenix-mcp-server");
    expect(manifest.version).toBe("1.3.0");
    expect(manifest.packages[0].version).toBe("1.3.0");
    expect(manifest.tools.map((t: any) => t.name)).toEqual(["check_safety_free", "preflight_network_health"]);
    expect(manifest.repository.url).toContain("x402-health-oracle");
    for (const tool of manifest.tools) expect(tool.annotations.readOnlyHint).toBe(true);
  });
});
