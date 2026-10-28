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
  it("free demo reasons give only PASS or FAIL, never DEGRADED (the free answer has no revert ratio)", () => {
    // Reasons the free /api/v1/demo/safe can return (zero/x402_gateway.py _demo_verdict + warming_up).
    const unsafeReasons = ["no_data", "data_stale", "chain_halted", "sequencer_stall", "high_latency", "warming_up"];
    for (const r of unsafeReasons) {
      const v = verdictFromChain(false, r);
      expect(["PASS", "FAIL"]).toContain(v.verdict);
      expect(v.verdict).not.toBe("DEGRADED");
      expect(v.verdict).toBe("FAIL");
      expect(v.reason).toBe(r);
    }
    const ok = verdictFromChain(true, "ok");
    expect(["PASS", "FAIL"]).toContain(ok.verdict);
    expect(ok.verdict).not.toBe("DEGRADED");
    expect(ok.verdict).toBe("PASS");
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
  it("preflight_network_health says the free answer is delayed and has no revert ratio, not 'right now'", () => {
    const d: string = tools["preflight_network_health"].description;
    expect(d).toContain("delayed");
    expect(d).toContain("does not include revert ratio");
    expect(d).not.toContain("right now");
  });
  it("price is dynamic: no fixed '$0.01' without 'from' in tool descriptions", () => {
    for (const name of Object.keys(tools)) {
      expect(tools[name].description).not.toMatch(/(?<!from )\$0\.01/);
    }
  });
});

describe("README matches the code", () => {
  it("has no XDP / rtt_ns claims, says eBPF is not used in the verdict, and names the latency and revert_ratio metrics", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const readme = fs.readFileSync(path.resolve(import.meta.dirname, "..", "README.md"), "utf-8");
    expect(readme).not.toMatch(/XDP/i);
    expect(readme).not.toMatch(/rtt_ns/i);
    expect(readme).toContain("not used in the verdict");
    expect(readme).toContain("latency");
    expect(readme).toContain("revert_ratio");
  });
  it("states the dynamic price (/api/v1/price) and the EIP-191 response signature", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const readme = fs.readFileSync(path.resolve(import.meta.dirname, "..", "README.md"), "utf-8");
    expect(readme).toContain("/api/v1/price");
    expect(readme).toContain("EIP-191");
  });
});

describe("server.json manifest", () => {
  it("matches the code: name, version, tools, read-only", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const manifest = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "..", "server.json"), "utf-8"));
    expect(manifest.name).toBe("io.github.kant19801201behax5/phoenix-mcp-server");
    expect(manifest.version).toBe("1.3.1");
    expect(manifest.packages[0].version).toBe("1.3.1");
    expect(manifest.tools.map((t: any) => t.name)).toEqual(["check_safety_free", "preflight_network_health"]);
    expect(manifest.repository.url).toContain("x402-health-oracle");
    expect(manifest.description.length).toBeLessThanOrEqual(100); // MCP registry rejects longer (422)
    for (const tool of manifest.tools) expect(tool.annotations.readOnlyHint).toBe(true);
  });
  it("manifest descriptions do not state a fixed price and do not promise DEGRADED", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const manifest = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "..", "server.json"), "utf-8"));
    const texts: string[] = [manifest.description, ...manifest.tools.map((t: any) => t.description)];
    for (const t of texts) {
      expect(t).not.toMatch(/(?<!from )\$0\.01/);
      expect(t).not.toContain("DEGRADED");
    }
  });
});
