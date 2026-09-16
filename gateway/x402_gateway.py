#!/usr/bin/env python3
"""
Phoenix Zero x402 Gateway — M2M API for AI agents.
Agents pay $0.01 USDC per call via x402 (Base mainnet).
Returns real-time sequencer health: P99, revert_ratio, recommendation.
"""
import json, time, os, hashlib, threading
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from multi_chain_probe import CHAINS as UPSTREAM_RPCS
from fastapi.middleware.cors import CORSMiddleware

# x402 imports
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http import HTTPFacilitatorClient, FacilitatorConfig, PaymentOption
from x402.http.types import RouteConfig
from x402.server import x402ResourceServer
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.mechanisms.evm.default_assets import DEFAULT_ASSETS as _EVM_ASSETS
_EVM_ASSETS["hedera:testnet"] = [{"asset": "0.0.0", "name": "HBAR", "version": "1", "decimals": 8, "symbol": "HBAR"}]
from x402.extensions.bazaar import declare_discovery_extension, OutputConfig

FEED_PATH = "/opt/phoenix_zero/data/feed.jsonl"

# ---------------------------------------------------------------------------
# Free demo tier: limited safe check without x402 payment
# ---------------------------------------------------------------------------
from collections import defaultdict

_demo_counter: dict[str, list] = {}  # IP -> [date_str, count]
_DEMO_DAILY_LIMIT = 100

def _demo_rate_ok(ip: str) -> bool:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entry = _demo_counter.get(ip)
    if not entry or entry[0] != today:
        _demo_counter[ip] = [today, 1]
        return True
    if entry[1] >= _DEMO_DAILY_LIMIT:
        return False
    entry[1] += 1
    return True

PAY_TO    = "0xbb967F16C7f3e9B4c1626680684445d41dBE44Ab"
NETWORK   = "eip155:8453"   # Base mainnet  # Base mainnet
PRICE     = "$0.01"   # Phase 66: raised from $0.0001 (SignalFuse charges $0.01)

app = FastAPI(
    root_path="/api",
    title="Phoenix Zero Sequencer Health API",
    description=(
        "Real-time L2 sequencer health oracle monitoring 12 chains: "
        "Base, Arbitrum, Optimism, zkSync, Blast, Linea, Mantle, Mode, Scroll, Taiko, Polygon zkEVM, Casper. "
        "Kernel-level eBPF RTT probes every 2 seconds + eth_getBlockReceipts revert analysis. "
        "Includes behavioral timing analysis for agent identity classification (CPU jitter entropy, Shannon entropy, Spearman rank correlation per paper Section 5). "
        "Payment: $0.01 USDC per call via x402 on Base mainnet."
    ),
    version="5.4.0",
    contact={"email": "aleksandrkent64@gmail.com"},
)

# ---------------------------------------------------------------------------
# x402 setup
# ---------------------------------------------------------------------------
from cdp.auth import get_auth_headers, GetAuthHeadersOptions
from x402.http import CreateHeadersAuthProvider

def _make_cdp_headers(method: str, path: str) -> dict[str, str]:
    key_id = os.environ.get("CDP_API_KEY_ID", "")
    secret = os.environ.get("CDP_API_SECRET", "")
    if not key_id or not secret:
        return {}
    opts = GetAuthHeadersOptions(
        api_key_id=key_id,
        api_key_secret=secret,
        request_method=method,
        request_host="api.cdp.coinbase.com",
        request_path=path,
    )
    return get_auth_headers(opts)

def _cdp_create_headers() -> dict[str, dict[str, str]]:
    return {
        "supported": _make_cdp_headers("GET",  "/platform/v2/x402/supported"),
        "verify":    _make_cdp_headers("POST", "/platform/v2/x402/verify"),
        "settle":    _make_cdp_headers("POST", "/platform/v2/x402/settle"),
    }

_cdp_key_id = os.environ.get("CDP_API_KEY_ID", "")
_cdp_secret  = os.environ.get("CDP_API_SECRET", "")

HEDERA_NETWORK = "hedera:testnet"
HEDERA_PAY_TO  = os.environ.get("HEDERA_PAY_TO", "")
BLOCKY402_URL  = "https://api.testnet.blocky402.com"

_facilitators = []

if _cdp_key_id and _cdp_secret:
    _cdp_auth = CreateHeadersAuthProvider(_cdp_create_headers)
    _facilitators.append(HTTPFacilitatorClient(FacilitatorConfig(
        url="https://api.cdp.coinbase.com/platform/v2/x402",
        auth_provider=_cdp_auth,
    )))
else:
    _FALLBACK_NETWORK = "eip155:84532"
    _facilitators.append(HTTPFacilitatorClient(FacilitatorConfig(url="https://x402.org/facilitator")))
    NETWORK = _FALLBACK_NETWORK

if HEDERA_PAY_TO:
    _facilitators.append(HTTPFacilitatorClient(FacilitatorConfig(url=BLOCKY402_URL)))

_server = x402ResourceServer(_facilitators)
_server.register(NETWORK, ExactEvmServerScheme())
if HEDERA_PAY_TO:
    _server.register(HEDERA_NETWORK, ExactEvmServerScheme())

_pay = [PaymentOption(scheme="exact", price=PRICE, network=NETWORK, pay_to=PAY_TO)]
if HEDERA_PAY_TO:
    _pay.append(PaymentOption(scheme="exact", price=PRICE, network=HEDERA_NETWORK, pay_to=HEDERA_PAY_TO, extra={"feePayer": "0.0.7162784"}))

_routes = {
    "GET /v1/health": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/health",
        accepts=_pay,
        description="Real-time L2 sequencer health across 12 chains (Base, Arbitrum, Optimism, zkSync, Blast, Linea, Mantle, Mode, Scroll, Taiko, Polygon zkEVM, Casper). Returns kernel-level P99/P95 RTT from eBPF probes, revert ratios (Base and Arbitrum via eth_getBlockReceipts), gas pressure, and execution recommendation.",
        service_name="Phoenix Zero L2 Health Oracle",
        tags=["l2", "sequencer", "health", "ebpf", "revert-ratio", "12-chain"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={
                    "timestamp": "2026-09-01T12:00:00Z",
                    "chains": {
                        "base":     {"p99_ms": 42.3, "p95_ms": 31.1, "stall": False, "updated": 1725188400},
                        "arbitrum": {"p99_ms": 55.7, "p95_ms": 38.2, "stall": False, "updated": 1725188400},
                        "optimism": {"p99_ms": 48.1, "p95_ms": 33.6, "stall": False, "updated": 1725188400},
                        "zksync":   {"p99_ms": 67.2, "p95_ms": 45.0, "stall": False, "updated": 1725188400},
                    },
                    "base_revert_ratio": 0.023,
                    "arb_revert_ratio": 0.011,
                    "gas_pressure": 12.5,
                    "blob_base_fee": 1,
                    "recommendation": "SAFE_TO_EXECUTE",
                    "source": "rtt.phoenix-ai.work",
                },
                schema={
                    "type": "object",
                    "properties": {
                        "timestamp":        {"type": "string", "description": "ISO 8601 UTC timestamp"},
                        "chains":           {"type": "object", "description": "Per-chain P99/P95 RTT in ms, stall flag, last-updated unix timestamp. Chains: base, arbitrum, optimism, zksync, blast, linea, mantle, mode, scroll, taiko, polygon_zkevm, casper"},
                        "base_revert_ratio": {"type": "number", "description": "Fraction of reverted txs on Base (0.0-1.0)"},
                        "arb_revert_ratio":  {"type": "number", "description": "Fraction of reverted txs on Arbitrum (0.0-1.0)"},
                        "gas_pressure":      {"type": "number", "description": "L1 gas price in gwei"},
                        "blob_base_fee":     {"type": "number", "description": "EIP-4844 blob base fee"},
                        "recommendation":    {"type": "string", "enum": ["SAFE_TO_EXECUTE", "ELEVATED_RISK", "HIGH_RISK", "STALL_DETECTED"]},
                    },
                },
            ),
        ),
    ),
    "GET /v1/safe": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/safe",
        accepts=_pay,
        description="Boolean pre-flight check for L2 transaction safety across all 12 chains (?chain= param, default: base). Returns safe=true/false with reason code. Revert ratio data available for Base and Arbitrum only (eth_getBlockReceipts); other chains use RTT-only analysis. Optimized for high-frequency agent calls.",
        service_name="Phoenix Zero Safe Check",
        tags=["l2", "safe", "pre-flight", "boolean"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={"safe": True, "chain": "base", "reason": "ok", "p99_ms": 42.3, "revert_ratio": 0.023, "revert_data_available": True},
                schema={
                    "type": "object",
                    "properties": {
                        "safe":          {"type": "boolean", "description": "true = safe to execute L2 transaction now"},
                        "reason":        {"type": "string", "enum": ["ok", "elevated_revert", "high_revert", "elevated_latency", "high_latency", "sequencer_stall", "data_stale"]},
                        "chain":         {"type": "string", "description": "Chain checked (default: base, supports all 12)"},
                        "p99_ms":        {"type": "number", "description": "Sequencer P99 RTT in milliseconds"},
                        "revert_ratio":  {"type": "number", "description": "Transaction revert ratio (0.0-1.0). null for chains without revert data."},
                        "revert_data_available": {"type": "boolean", "description": "True if revert ratio is measured for this chain (Base and Arbitrum only)"},
                    },
                },
            ),
        ),
    ),
    "GET /v1/price": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/price",
        accepts=_pay,
        description="Current x402 pricing with surge multiplier. Price increases 10x during sequencer stalls and MEV storms.",
        service_name="Phoenix Zero Pricing",
        tags=["pricing", "surge"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={
                    "current_price_usdc": "$0.01",
                    "surge_multiplier": 1.0,
                    "normal_price_usdc": "$0.01",
                    "recommendation": "SAFE_TO_EXECUTE",
                },
            ),
        ),
    ),
    "GET /v1/chains/:chain": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/chains/{chain}",
        accepts=_pay,
        description="Single-chain sequencer health. Returns P99/P95 RTT, stall flag, revert ratio for one of 12 monitored L2 chains.",
        service_name="Phoenix Zero Chain Health",
        tags=["l2", "single-chain", "sequencer"],
        extensions=declare_discovery_extension(
            path_params_schema={
                "properties": {
                    "chain": {
                        "type": "string",
                        "enum": ["base", "arbitrum", "optimism", "zksync", "blast", "linea", "mantle", "mode", "scroll", "taiko", "polygon_zkevm", "casper"],
                        "description": "L2 chain name",
                    },
                },
                "required": ["chain"],
            },
            output=OutputConfig(
                example={
                    "chain": "base",
                    "p99_ms": 42.3,
                    "p95_ms": 31.1,
                    "stall": False,
                    "revert_ratio": 0.023,
                    "updated": 1725188400,
                    "recommendation": "SAFE_TO_EXECUTE",
                },
            ),
        ),
    ),
    "POST /v1/classify": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/classify",
        accepts=_pay,
        description="Silicon DNA agent identity classification. Behavioral timing analysis: CPU jitter entropy (L0), Shannon entropy (L2), Spearman rank correlation (L3) to classify as HUMAN, LEGIT_AGENT, or MALICIOUS_BOT. Per paper Section 5.1.",
        service_name="Silicon DNA Classifier",
        tags=["identity", "bot-detection", "sybil", "behavioral-timing"],
        extensions=declare_discovery_extension(
            input={"headers": {"user-agent": "Mozilla/5.0"}, "ip": "1.2.3.4"},
            input_schema={
                "properties": {
                    "headers": {"type": "object", "description": "HTTP request headers to analyze"},
                    "ip":      {"type": "string", "description": "Client IP address"},
                },
            },
            body_type="json",
            output=OutputConfig(
                example={
                    "verdict": "LEGIT_AGENT",
                    "confidence": 0.92,
                    "signals": {"tls_fp": "chrome", "jitter": "natural", "entropy": 3.2},
                },
            ),
        ),
    ),
    "POST /v1/preflight": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/preflight",
        accepts=_pay,
        description="Deterministic pre-flight transaction safety decision. Returns PASS/DEGRADED/FAIL with cryptographic evidence of observed network state at decision time. Machine-readable policy. Designed for autonomous agents that need provable execution decisions.",
        service_name="Phoenix Zero Preflight",
        tags=["preflight", "decision", "autonomous", "provable", "transaction-safety"],
        extensions=declare_discovery_extension(
            input={"chain": "base"},
            input_schema={
                "properties": {
                    "chain": {"type": "string", "enum": ["base", "arbitrum", "optimism", "zksync", "blast", "linea", "mantle", "mode", "scroll", "taiko", "polygon_zkevm", "casper"], "description": "Target L2 chain for transaction"},
                },
                "required": ["chain"],
            },
            body_type="json",
            output=OutputConfig(
                example={
                    "decision": "PASS",
                    "chain": "base",
                    "observed_at": "2026-09-08T14:00:00Z",
                    "freshness_ms": 420,
                    "rtt_p99_ms": 37.2,
                    "revert_ratio": 0.002,
                    "stall_flag": 0,
                    "gas_pressure": 0.45,
                    "blob_base_fee": 0.001,
                    "policy": "normal-v1",
                    "evidence_id": "a3c2e5e8a5a2e4f0c8e0e3f4b6a8d7c9",
                },
                schema={
                    "type": "object",
                    "properties": {
                        "decision":      {"type": "string", "enum": ["PASS", "DEGRADED", "FAIL"], "description": "Deterministic execution decision"},
                        "chain":         {"type": "string", "description": "Target chain evaluated"},
                        "observed_at":   {"type": "string", "description": "ISO 8601 UTC timestamp of observation"},
                        "freshness_ms":  {"type": "integer", "description": "Age of latest measurement in milliseconds"},
                        "rtt_p99_ms":    {"type": "number", "description": "P99 RTT to chain sequencer in ms"},
                        "revert_ratio":  {"type": "number", "description": "Transaction revert ratio (0.0-1.0)"},
                        "stall_flag":    {"type": "integer", "description": "0=none, 1=stall, 2=slow-creep"},
                        "gas_pressure":  {"type": "number", "description": "L1 gas utilization ratio (0.0-1.0)"},
                        "blob_base_fee": {"type": "number", "description": "EIP-4844 blob base fee normalized"},
                        "policy":        {"type": "string", "description": "Policy version applied to make decision"},
                        "evidence_id":   {"type": "string", "description": "SHA-256 hash of decision inputs — proves this decision was made from this exact state"},
                    },
                },
            ),
        ),
    ),
    "GET /v1/health-proof": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/health-proof",
        accepts=_pay,
        description="HMAC-SHA256 integrity commitment over node health assessment and eBPF XDP/LSM status. Provides tamper evidence (BLAKE3+Ed25519 per paper Section 6.3). Not a zero-knowledge proof.",
        service_name="Silicon DNA Health Proof",
        tags=["integrity-proof", "health", "ebpf", "commitment", "verifiable"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={
                    "node": {
                        "health": "operational",
                        "uptime_s": 86400,
                        "version": "5.4.0",
                        "threat_score": 0.05,
                        "layers_passed": "11000111",
                        "trust_ratio": 0.998,
                        "ebpf": {"xdp_shield": True, "lsm_guard": False, "banned_ips": 3},
                    },
                    "proof": {
                        "commitment": "c334f6106a1e6e184111607dcfb657e897bebad20d552fad3c2798112cc65ad0",
                        "salt": "6e0b46994d858b1488f495166a43e70c",
                        "layersBitmap": 134,
                        "ts": 1725188400000,
                        "ip_hash": "12ca17b49af22894",
                        "version": 1,
                    },
                },
                schema={
                    "type": "object",
                    "properties": {
                        "node":  {"type": "object", "description": "Node health: status, uptime, version, 8-layer security bitmap, trust ratio, eBPF XDP/LSM status"},
                        "proof": {"type": "object", "description": "HMAC-SHA256 commitment over health metrics. Verifiable without revealing raw values. Includes salt, layer bitmap, timestamp, IP hash"},
                    },
                },
            ),
        ),
    ),
    "GET /v1/correlation": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/correlation",
        accepts=_pay,
        description="12x12 cross-chain temporal correlation matrix R_xy and Frobenius anomaly score A(t). Paper Section 3: synchronized activity detection across all chains. A spike in A(t) indicates a new coordinated source (MEV cluster, bot farm).",
        service_name="Silicon DNA Correlation Matrix",
        tags=["correlation", "cross-chain", "anomaly", "frobenius", "r_xy", "bot-detection"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={
                    "matrix": {"base_arbitrum": 0.42, "base_optimism": 0.31, "arbitrum_zksync": 0.89},
                    "max_correlation": 0.89,
                    "sync_pairs": [["arbitrum", "zksync", 0.89]],
                    "sync_pair_count": 1,
                    "anomaly_score": 2.34,
                    "anomaly_flag": True,
                    "baseline_samples": 50,
                    "chains_active": 12,
                    "window_samples": 30,
                },
                schema={
                    "type": "object",
                    "properties": {
                        "matrix":           {"type": "object", "description": "Pearson R_xy for all 66 unique chain pairs"},
                        "max_correlation":  {"type": "number", "description": "Highest |R_xy| across all pairs (0.0-1.0)"},
                        "sync_pairs":       {"type": "array",  "description": "Chain pairs with |R_xy| > 0.85"},
                        "anomaly_score":    {"type": "number", "description": "Frobenius norm A(t) = ||R_window - R_baseline||_F"},
                        "anomaly_flag":     {"type": "boolean","description": "True when A(t) > threshold"},
                    },
                },
            ),
        ),
    ),
}
class CacheControlMiddleware:
    """Add Cache-Control: no-store to 402 responses so payment challenges are never cached."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        async def send_with_cc(message):
            if message['type'] == 'http.response.start' and message.get('status') == 402:
                headers = list(message.get('headers', []))
                headers.append((b'cache-control', b'no-store'))
                message = {**message, 'headers': headers}
            await send(message)

        await self.app(scope, receive, send_with_cc)


# ---------------------------------------------------------------------------
# Silicon DNA gate — real identity check, not just a documented aspiration.
# Rejects callers Silicon DNA has already flagged as bots BEFORE they're even
# asked to pay (this middleware is registered last, so it sits outermost,
# ahead of PaymentMiddlewareASGI — see the ordering note below add_middleware
# calls). Queries Silicon DNA's own ban list via a localhost-only endpoint.
# Fails open (never blocks) on any error or timeout: a Silicon DNA hiccup
# must never take down paid access to this gateway.
# ---------------------------------------------------------------------------
import httpx

SILICON_DNA_CHECK_URL = os.environ.get("SILICON_DNA_CHECK_URL", "http://127.0.0.1:3001/api/check-ip")
_silicon_dna_client = httpx.AsyncClient(timeout=0.5)

class SiliconDnaGateMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith('/v1/'):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get('headers') or [])
        client_ip = headers.get(b'x-real-ip', b'').decode() or (scope.get('client') or ('', 0))[0]

        banned = False
        if client_ip:
            try:
                r = await _silicon_dna_client.get(SILICON_DNA_CHECK_URL, params={"ip": client_ip})
                if r.status_code == 200:
                    banned = bool(r.json().get("banned"))
            except Exception:
                banned = False  # fail open

        if banned:
            body = json.dumps({
                "error": "blocked_by_silicon_dna",
                "detail": "This IP was flagged by Silicon DNA's bot detection and cannot access paid endpoints.",
            }).encode()
            await send({"type": "http.response.start", "status": 403,
                         "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)


# Middleware order matters: Starlette wraps outermost-last, so the LAST
# add_middleware() call here runs FIRST on every request. SiliconDnaGate is
# added last so it intercepts and can reject a request before
# PaymentMiddlewareASGI ever asks the caller to pay.
app.add_middleware(PaymentMiddlewareASGI, routes=_routes, server=_server)
app.add_middleware(CacheControlMiddleware)
app.add_middleware(SiliconDnaGateMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*", "X-PAYMENT", "payment-required"],
    expose_headers=["X-PAYMENT", "payment-required", "www-authenticate"],
)

# ---------------------------------------------------------------------------
# Silicon DNA — Agent fingerprinting
# ---------------------------------------------------------------------------
_KEYS_PATH = "/opt/phoenix_zero/authorized_keys.json"

def _save_agent_fingerprint(from_address: str, endpoint: str) -> None:
    """On first x402 payment, fingerprint the agent by its ETH address.
    Saved agents are never rate-limited or blocked."""
    try:
        addr = from_address.lower().strip()
        if not addr.startswith("0x") or len(addr) != 42:
            return
        key_hash = hashlib.sha256(addr.encode()).hexdigest()
        try:
            with open(_KEYS_PATH) as f:
                keys = json.load(f)
        except Exception:
            keys = {}
        if key_hash in keys:
            return  # already known
        keys[key_hash] = {
            "client_name": f"agent:{addr[:10]}",
            "tier": "agent_verified",
            "expiry": int(time.time()) + 365 * 86400,
            "eth_address": addr,
            "first_seen": int(time.time()),
            "first_endpoint": endpoint,
        }
        with open(_KEYS_PATH, "w") as f:
            json.dump(keys, f, indent=2)
    except Exception:
        pass  # fingerprinting must never break the response

def _fingerprint_from_payment(request: Request) -> None:
    """Extract payer address from x402 payment header and save fingerprint."""
    x_pay = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
    if not x_pay:
        return
    fa = ""
    # Primary: x402 SDK decode
    try:
        from x402.http.utils import decode_payment_signature_header
        pl = decode_payment_signature_header(x_pay)
        p = pl.payload if hasattr(pl, "payload") else (pl if isinstance(pl, dict) else {})
        if isinstance(p, dict):
            fa = ((p.get("authorization") or {}).get("from") or
                  p.get("from_address") or p.get("from") or "")
    except Exception as e:
        print(f"[FINGERPRINT] SDK decode error: {e}")
    # Fallback: raw base64 decode
    if not fa:
        try:
            import base64
            raw = base64.b64decode(x_pay + "=" * (-len(x_pay) % 4))
            d = json.loads(raw)
            p = d.get("payload", d)
            if isinstance(p, dict):
                fa = ((p.get("authorization", {}).get("from") or
                       p.get("from_address") or p.get("from") or ""))
        except Exception:
            pass
    if fa:
        _save_agent_fingerprint(fa, str(request.url.path))
        print(f"[FINGERPRINT] Saved: {fa[:10]}... on {request.url.path}")
    elif x_pay:
        print(f"[FINGERPRINT] No from_address in X-PAYMENT ({len(x_pay)}b)")

# ---------------------------------------------------------------------------
# Data reader
# ---------------------------------------------------------------------------
def _read_latest():
    metrics = {}   # chain -> latest PHOENIX_METRIC record
    health  = None # latest PHOENIX_L2_HEALTH
    eth_sig = None # latest PHOENIX_ETH_SIGNAL
    corr    = None # latest SILICON_DNA_CORRELATION (12x12 R_xy matrix)

    try:
        with open(FEED_PATH, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            read_bytes = min(size, 256 * 1024)  # last 256KB
            f.seek(size - read_bytes)
            raw = f.read().decode("utf-8", errors="ignore")
        for line in raw.splitlines():
            try:
                r = json.loads(line)
                t = r.get("type")
                if t == "PHOENIX_METRIC":
                    c = r.get("chain")
                    if c:
                        metrics[c] = r
                elif t == "PHOENIX_L2_HEALTH":
                    health = r
                elif t == "PHOENIX_ETH_SIGNAL":
                    eth_sig = r
                elif t == "SILICON_DNA_CORRELATION":
                    corr = r
            except Exception:
                pass
    except Exception:
        pass
    return metrics, health, eth_sig, corr

_L1_CHAINS = {"casper"}
_L1_P99_THRESHOLD = 2000

def _recommendation(metrics, health):
    worst = "SAFE_TO_EXECUTE"
    h = health or {}
    for chain, data in metrics.items():
        p99 = data.get("p99_ms", 0)
        stall = data.get("stall_flag", False)
        rev = 0
        if chain == "arbitrum":
            rev = h.get("arb_revert_ratio", 0)
        elif chain == "base":
            rev = h.get("base_revert_ratio", 0)
        high_thresh = _L1_P99_THRESHOLD if chain in _L1_CHAINS else 500
        elevated_thresh = 1000 if chain in _L1_CHAINS else 200
        stall_thresh = 10000 if chain in _L1_CHAINS else 5000
        if stall or p99 >= stall_thresh:
            return "STALL_DETECTED"
        if p99 > high_thresh or rev > 0.30:
            worst = "HIGH_RISK"
        elif (p99 > elevated_thresh or rev > 0.10) and worst == "SAFE_TO_EXECUTE":
            worst = "ELEVATED_RISK"
    return worst

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/v1/health", summary="Full sequencer health snapshot (all chains)")
async def get_health(request: Request):
    _fingerprint_from_payment(request)
    metrics, health, eth_sig, _ = _read_latest()
    now = datetime.now(timezone.utc).isoformat()

    chains = {}
    for chain, r in metrics.items():
        chains[chain] = {
            "p99_ms":  r.get("p99_ms"),
            "p95_ms":  r.get("p95_ms"),
            "stall":   r.get("stall_flag", False),
            "updated": r.get("_ts"),
        }

    h = health or {}
    e = eth_sig or {}

    return {
        "timestamp":      now,
        "chains":         chains,
        "base_revert_ratio":  h.get("base_revert_ratio"),
        "arb_revert_ratio":   h.get("arb_revert_ratio"),
        "gas_pressure":       e.get("gas_pressure"),
        "blob_base_fee":      e.get("blob_base_fee"),
        "recommendation":     _recommendation(metrics, health),
        "source":             "rtt.phoenix-ai.work",
    }

@app.get("/v1/chains/{chain}", summary="Single-chain health (base|arbitrum|optimism|zksync)")
async def get_chain(chain: str, request: Request):
    _fingerprint_from_payment(request)
    metrics, health, _, _ = _read_latest()
    r = metrics.get(chain.lower())
    if not r:
        return JSONResponse(status_code=404, content={"error": f"chain '{chain}' not found"})

    rev = None
    if chain.lower() == "base" and health:
        rev = health.get("base_revert_ratio")
    elif chain.lower() == "arbitrum" and health:
        rev = health.get("arb_revert_ratio")

    return {
        "chain":        chain.lower(),
        "p99_ms":       r.get("p99_ms"),
        "p95_ms":       r.get("p95_ms"),
        "stall":        r.get("stall_flag", False),
        "revert_ratio": rev,
        "updated":      r.get("_ts"),
        "recommendation": _recommendation({chain.lower(): r}, {"base_revert_ratio": rev} if rev else None),
    }


# ---------------------------------------------------------------------------
# /v1/safe — Boolean endpoint for agents (true/false + reason)
# /v1/price — Dynamic surge pricing info
# ---------------------------------------------------------------------------

PRICE_NORMAL = "$0.01"
PRICE_SURGE  = "$0.10"

def _surge_price(metrics, health) -> tuple[str, float]:
    """Return (price_string, multiplier). Surge 10x during MEV storms."""
    base = metrics.get("base", {})
    p99  = base.get("p99_ms", 0)
    rev  = (health or {}).get("base_revert_ratio", 0)
    if p99 >= 5000 or rev >= 0.30:
        return PRICE_SURGE, 10.0
    if p99 > 200 or rev > 0.10:
        return "$0.03", 3.0
    return PRICE_NORMAL, 1.0


# Dynamic surge pricing: updates x402 payment challenge every 10s
def _surge_price_daemon():
    time.sleep(5)
    while True:
        try:
            result = _read_latest()
            metrics, health = result[0], result[1]
            price, _ = _surge_price(metrics, health)
            _pay[0] = PaymentOption(scheme="exact", price=price, network=NETWORK, pay_to=PAY_TO)
            if len(_pay) > 1 and HEDERA_PAY_TO:
                _pay[1] = PaymentOption(scheme="exact", price=price, network=HEDERA_NETWORK, pay_to=HEDERA_PAY_TO, extra={"feePayer": "0.0.7162784"})
        except Exception:
            pass
        time.sleep(10)

threading.Thread(target=_surge_price_daemon, daemon=True, name="surge-pricing").start()


_SAFE_VALID_CHAINS = set(UPSTREAM_RPCS)

@app.get(
    "/v1/safe",
    summary="Boolean safety check for agents — cheapest endpoint",
    description=(
        "Returns a single boolean: safe=true means execute now, safe=false means wait. "
        "Supports all 12 chains via ?chain= query param (default: base). "
        "Reason codes: ok | elevated_revert | high_revert | sequencer_stall | data_stale"
    ),
)
async def get_safe(request: Request):
    _fingerprint_from_payment(request)
    chain = (request.query_params.get("chain") or "base").lower().strip()
    if chain not in _SAFE_VALID_CHAINS:
        return JSONResponse(status_code=400, content={
            "error": f"unknown chain: {chain}", "supported": sorted(_SAFE_VALID_CHAINS),
        })
    is_l1 = chain in _L1_CHAINS
    metrics, health, _, _ = _read_latest()
    r = metrics.get(chain, {})
    p99  = r.get("p99_ms", 0)
    stall = r.get("stall_flag", False)
    ts   = r.get("_ts", 0)

    # Revert ratio: only available for Base and Arbitrum (eth_getBlockReceipts)
    rev = None
    revert_available = False
    if chain == "base" and health:
        rev = (health or {}).get("base_revert_ratio")
        revert_available = rev is not None
    elif chain == "arbitrum" and health:
        rev = (health or {}).get("arb_revert_ratio")
        revert_available = rev is not None
    rev_val = rev if rev is not None else 0.0

    stall_thresh = 10000 if is_l1 else 5000
    high_thresh = 2000 if is_l1 else 500
    elev_thresh = 1000 if is_l1 else 200

    resp = {"chain": chain, "p99_ms": p99, "revert_ratio": round(rev_val, 4) if revert_available else None, "revert_data_available": revert_available}

    if ts and (time.time() - ts) > 30:
        return {"safe": False, "reason": "data_stale", "age_s": round(time.time() - ts), **resp}
    if stall or p99 >= stall_thresh:
        return {"safe": False, "reason": "sequencer_stall", **resp}
    if revert_available and rev >= 0.30:
        return {"safe": False, "reason": "high_revert", **resp}
    if p99 > high_thresh:
        return {"safe": False, "reason": "high_latency", **resp}
    if revert_available and rev >= 0.10:
        return {"safe": False, "reason": "elevated_revert", **resp}
    if p99 > elev_thresh:
        return {"safe": False, "reason": "elevated_latency", **resp}

    return {"safe": True, "reason": "ok", **resp}


@app.get("/v1/price", summary="Current x402 pricing (surge during MEV storms)", include_in_schema=True)
async def get_price(request: Request):
    _fingerprint_from_payment(request)
    metrics, health, _, _ = _read_latest()
    price, mult = _surge_price(metrics, health)
    rec = _recommendation(metrics, health)
    return {
        "current_price_usdc": price,
        "surge_multiplier":   mult,
        "normal_price_usdc":  PRICE_NORMAL,
        "surge_price_usdc":   PRICE_SURGE,
        "recommendation":     rec,
        "note": "Price increases 10x during sequencer stall / MEV war. Data is most valuable when the network is most dangerous.",
    }


# ---------------------------------------------------------------------------
# /v1/classify — Silicon DNA agent identity (x402-paid). Proxies to Silicon
# DNA's classifier on :3001; returns HUMAN / LEGIT_AGENT / MALICIOUS_BOT.
# Additive: does not touch the sequencer-health endpoints above. The existing
# free /api/classify (:3001) is unchanged; this is the paid, x402-gated tier.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# /v1/preflight — Deterministic execution decision with provable evidence.
# Reads live feed, applies stable policy, returns PASS/DEGRADED/FAIL + evidence_id.
# ---------------------------------------------------------------------------
PREFLIGHT_POLICY = "normal-v1"
_L1_CHAINS_PF = {"casper"}

def _preflight_decision(chain: str, metrics: dict, health: dict | None, eth_sig: dict | None) -> dict:
    now_ms = int(time.time() * 1000)
    r = metrics.get(chain, {})
    p99 = r.get("p99_ms", 0) or 0
    stall = r.get("stall_flag", 0) or 0
    ts = r.get("_ts", 0) or 0
    freshness_ms = int((time.time() - ts) * 1000) if ts else 99999

    rev = None
    if chain == "base" and health:
        rev = health.get("base_revert_ratio")
    elif chain == "arbitrum" and health:
        rev = health.get("arb_revert_ratio")
    rev = rev if rev is not None else 0.0

    gas_p = (eth_sig or {}).get("gas_pressure", 0) or 0
    blob = (eth_sig or {}).get("blob_base_fee", 0) or 0

    is_l1 = chain in _L1_CHAINS_PF
    p99_fail = 2000 if is_l1 else 500
    p99_deg = 1000 if is_l1 else 200
    stall_fail = 10000 if is_l1 else 5000

    if freshness_ms > 60000:
        decision = "FAIL"
    elif stall == 1 or p99 >= stall_fail:
        decision = "FAIL"
    elif p99 > p99_fail or rev > 0.30:
        decision = "FAIL"
    elif p99 > p99_deg or rev > 0.10 or freshness_ms > 30000:
        decision = "DEGRADED"
    else:
        decision = "PASS"

    observed_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else datetime.now(timezone.utc).isoformat()

    evidence_input = f"{chain}|{observed_at}|{p99}|{rev}|{stall}|{gas_p}|{blob}|{PREFLIGHT_POLICY}"
    evidence_id = hashlib.sha256(evidence_input.encode()).hexdigest()

    return {
        "decision": decision,
        "chain": chain,
        "observed_at": observed_at,
        "freshness_ms": freshness_ms,
        "rtt_p99_ms": round(p99, 2),
        "revert_ratio": round(rev, 4),
        "stall_flag": stall,
        "gas_pressure": round(gas_p, 4),
        "blob_base_fee": round(blob, 6),
        "policy": PREFLIGHT_POLICY,
        "evidence_id": evidence_id,
    }

@app.post("/v1/preflight", summary="Deterministic pre-flight decision — PASS / DEGRADED / FAIL with evidence")
async def preflight(request: Request):
    _fingerprint_from_payment(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    chain = (body.get("chain") or "base").lower().strip()
    valid_chains = set(UPSTREAM_RPCS)
    if chain not in valid_chains:
        return JSONResponse(status_code=400, content={
            "error": f"unknown chain: {chain}",
            "supported": sorted(valid_chains),
        })
    metrics, health, eth_sig, _ = _read_latest()
    return _preflight_decision(chain, metrics, health, eth_sig)


_CLASSIFY_URL = os.environ.get("SILICON_DNA_CLASSIFY_URL", "http://127.0.0.1:3001/api/classify")
_classify_client = httpx.AsyncClient(timeout=3.0)

@app.post("/v1/classify", summary="Silicon DNA agent identity — HUMAN / LEGIT_AGENT / MALICIOUS_BOT")
async def classify(request: Request):
    try:
        body = await request.body()
        r = await _classify_client.post(
            _CLASSIFY_URL, content=body,
            headers={"content-type": request.headers.get("content-type", "application/json")},
        )
        try:
            payload = r.json()
        except Exception:
            payload = {"raw": r.text}
        return JSONResponse(status_code=r.status_code, content=payload)
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "classify_upstream_error", "detail": str(e)})


_HEALTH_PROOF_URL = os.environ.get("SILICON_DNA_HEALTH_PROOF_URL", "http://127.0.0.1:3001/api/health-proof")
_health_proof_client = httpx.AsyncClient(timeout=3.0)

@app.get("/v1/health-proof", summary="Cryptographic proof of node health — verifiable HMAC commitment")
async def health_proof(request: Request):
    _fingerprint_from_payment(request)
    try:
        r = await _health_proof_client.get(_HEALTH_PROOF_URL)
        try:
            payload = r.json()
        except Exception:
            payload = {"raw": r.text}
        return JSONResponse(status_code=r.status_code, content=payload)
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "health_proof_upstream_error", "detail": str(e)})


@app.get("/v1/correlation", summary="12x12 cross-chain correlation matrix R_xy and Frobenius anomaly score A(t)")
async def get_correlation(request: Request):
    _fingerprint_from_payment(request)
    result = _read_latest()
    corr = result[3] if len(result) > 3 else None
    if not corr:
        return JSONResponse(status_code=503, content={
            "error": "correlation_data_not_ready",
            "detail": "Cross-chain correlation matrix requires min 10 samples per chain. Builds up ~30s after probe starts.",
        })
    return {
        "matrix": corr.get("matrix", {}),
        "max_correlation": corr.get("max_correlation", 0),
        "sync_pairs": corr.get("sync_pairs", []),
        "sync_pair_count": corr.get("sync_pair_count", 0),
        "anomaly_score": corr.get("anomaly_score", 0),
        "anomaly_flag": corr.get("anomaly_flag", False),
        "baseline_samples": corr.get("baseline_samples", 0),
        "chains_active": corr.get("chains_active", 0),
        "window_samples": corr.get("window_samples", 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "rtt.phoenix-ai.work",
    }



@app.get("/v1/demo/safe", summary="FREE demo — safe/unsafe check (limited data, 100/day/IP)",
         tags=["demo"], include_in_schema=True)
async def demo_safe(request: Request):
    """Free pre-flight safety check with limited data. No payment required.
    Returns safe=true/false + reason. Full details (P99, revert ratio, correlation)
    available via paid /v1/safe endpoint ($0.01 USDC).
    Rate limit: 100 calls per IP per UTC day."""
    ip = request.headers.get("x-real-ip", request.client.host if request.client else "0.0.0.0")
    if not _demo_rate_ok(ip):
        return JSONResponse(status_code=429, content={
            "error": "demo_limit_exceeded",
            "message": "Free tier: 100 calls/day. Pay $0.01 USDC for unlimited access.",
            "upgrade": "GET /v1/safe (x402 payment)",
            "limit": _DEMO_DAILY_LIMIT,
        })
    chain = (request.query_params.get("chain") or "base").lower().strip()
    if chain not in _SAFE_VALID_CHAINS:
        return JSONResponse(status_code=400, content={
            "error": f"unknown chain: {chain}", "supported": sorted(_SAFE_VALID_CHAINS),
        })
    metrics, health, _, _ = _read_latest()
    r = metrics.get(chain, {})
    p99 = r.get("p99_ms", 0)
    stall = r.get("stall_flag", False)
    ts = r.get("_ts", 0)
    is_l1 = chain in _L1_CHAINS
    stall_thresh = 10000 if is_l1 else 5000
    high_thresh = 2000 if is_l1 else 500

    safe = True
    reason = "ok"
    if ts and (time.time() - ts) > 30:
        safe, reason = False, "data_stale"
    elif stall or p99 >= stall_thresh:
        safe, reason = False, "sequencer_stall"
    elif p99 > high_thresh:
        safe, reason = False, "high_latency"

    corr_data = _read_latest()[3]

    teaser = {
        "p99_latency_ms": "HIDDEN_IN_DEMO — pay $0.01 for real-time P99",
        "revert_ratio": "HIDDEN_IN_DEMO — Base+Arb revert data via /v1/safe",
        "correlation_pairs": corr_data.get("sync_pair_count", 0) if corr_data else 0,
        "anomaly_score": "HIDDEN_IN_DEMO — Frobenius A(t) via /v1/correlation",
        "chains_monitored": 12,
        "update_interval_s": 2,
        "silicon_dna_layers": 9,
        "endpoints_available": {
            "/v1/safe": "$0.01 — full P99, revert ratio, per-chain query",
            "/v1/health": "$0.01 — all 12 chains snapshot",
            "/v1/correlation": "$0.01 — 12x12 R_xy matrix + anomaly detection",
            "/v1/classify": "$0.01 — HUMAN / LEGIT_AGENT / MALICIOUS_BOT",
            "/v1/preflight": "$0.01 — PASS/DEGRADED/FAIL with evidence_id",
        },
    }

    return {
        "safe": safe,
        "reason": reason,
        "chain": chain,
        "demo": True,
        "teaser": teaser,
        "upgrade": "GET /api/v1/safe — full P99, revert ratio, correlation ($0.01 USDC via x402)",
    }

@app.get("/", include_in_schema=False)
async def root():
    return {"service": "Phoenix Zero x402 API", "docs": "/docs", "payment": PRICE + " USDC per call via x402"}

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"error": "internal_error"})

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=3002, log_level="info")