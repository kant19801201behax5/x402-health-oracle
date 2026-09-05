#!/usr/bin/env python3
"""
Phoenix Zero x402 Gateway — M2M API for AI agents.
Agents pay $0.01 USDC per call via x402 (Base mainnet).
Returns real-time sequencer health: P99, revert_ratio, recommendation.
"""
import json, time, os, hashlib
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
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
        "Includes agent identity classification via physical-layer NIC fingerprinting. "
        "Payment: $0.01 USDC per call via x402 on Base mainnet."
    ),
    version="5.3.0",
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
        description="Real-time L2 sequencer health across 12 chains (Base, Arbitrum, Optimism, zkSync, Blast, Linea, Mantle, Mode, Scroll, Taiko, Polygon zkEVM, Casper). Returns kernel-level P99/P95 RTT from eBPF probes, revert ratios, gas pressure, and execution recommendation.",
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
        description="Boolean pre-flight check for L2 transaction safety. Returns safe=true/false with reason code. Optimized for high-frequency agent calls before submitting transactions.",
        service_name="Phoenix Zero Safe Check",
        tags=["l2", "safe", "pre-flight", "boolean"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={"safe": True, "reason": "ok", "base_p99_ms": 42.3, "revert_ratio": 0.023},
                schema={
                    "type": "object",
                    "properties": {
                        "safe":          {"type": "boolean", "description": "true = safe to execute L2 transaction now"},
                        "reason":        {"type": "string", "enum": ["ok", "elevated_revert", "high_revert", "sequencer_stall", "data_stale"]},
                        "base_p99_ms":   {"type": "number", "description": "Base sequencer P99 RTT in milliseconds"},
                        "revert_ratio":  {"type": "number", "description": "Base revert ratio (0.0-1.0)"},
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
                    "normal_price_usdc": "$0.0001",
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
        description="Silicon DNA agent identity classification. Analyzes TLS fingerprint, timing jitter, behavioral entropy to classify as HUMAN, LEGIT_AGENT, or MALICIOUS_BOT. Physical-layer NIC fingerprinting.",
        service_name="Silicon DNA Classifier",
        tags=["identity", "bot-detection", "sybil", "nic-fingerprint"],
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
    "GET /v1/health-proof": RouteConfig(
        resource="https://rtt.phoenix-ai.work/api/v1/health-proof",
        accepts=_pay,
        description="Cryptographic proof of node health. HMAC-SHA256 commitment over 8-layer security assessment (PQC, Frankenstein, Spearman, entropy, jitter) plus eBPF XDP/LSM status. Verifiable without revealing raw metrics.",
        service_name="Silicon DNA Health Proof",
        tags=["zkproof", "health", "ebpf", "commitment", "verifiable"],
        extensions=declare_discovery_extension(
            output=OutputConfig(
                example={
                    "node": {
                        "health": "operational",
                        "uptime_s": 86400,
                        "version": "5.0.0",
                        "threat_score": 0.05,
                        "layers_passed": "10000110",
                        "trust_ratio": 0.998,
                        "ebpf": {"xdp_shield": True, "lsm_guard": True, "banned_ips": 3},
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

# ---------------------------------------------------------------------------
# Data reader
# ---------------------------------------------------------------------------
def _read_latest():
    metrics = {}   # chain -> latest PHOENIX_METRIC record
    health  = None # latest PHOENIX_L2_HEALTH
    eth_sig = None # latest PHOENIX_ETH_SIGNAL

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
            except Exception:
                pass
    except Exception:
        pass
    return metrics, health, eth_sig

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
    # Silicon DNA: fingerprint paying agent (x402 already verified payment)
    _x_pay = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
    if _x_pay:
        try:
            from x402.http.utils import decode_payment_signature_header
            _pl = decode_payment_signature_header(_x_pay)
            _fa = (_pl.payload.get("authorization") or {}).get("from") or                   _pl.payload.get("from_address") or _pl.payload.get("from") or ""
            if _fa:
                _save_agent_fingerprint(_fa, str(request.url.path))
        except Exception:
            pass
    metrics, health, eth_sig = _read_latest()
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
    # Silicon DNA: fingerprint paying agent (x402 already verified payment)
    _x_pay = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
    if _x_pay:
        try:
            from x402.http.utils import decode_payment_signature_header
            _pl = decode_payment_signature_header(_x_pay)
            _fa = (_pl.payload.get("authorization") or {}).get("from") or                   _pl.payload.get("from_address") or _pl.payload.get("from") or ""
            if _fa:
                _save_agent_fingerprint(_fa, str(request.url.path))
        except Exception:
            pass
    metrics, health, _ = _read_latest()
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


@app.get(
    "/v1/safe",
    summary="Boolean safety check for agents — cheapest endpoint",
    description=(
        "Returns a single boolean: safe=true means execute now, safe=false means wait. "
        "Optimized for high-frequency agent pre-flight checks. "
        "Reason codes: ok | elevated_revert | high_revert | sequencer_stall | data_stale"
    ),
)
async def get_safe(request: Request):
    # Silicon DNA: fingerprint paying agent (x402 already verified payment)
    _x_pay = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
    if _x_pay:
        try:
            from x402.http.utils import decode_payment_signature_header
            _pl = decode_payment_signature_header(_x_pay)
            _fa = (_pl.payload.get("authorization") or {}).get("from") or                   _pl.payload.get("from_address") or _pl.payload.get("from") or ""
            if _fa:
                _save_agent_fingerprint(_fa, str(request.url.path))
        except Exception:
            pass
    metrics, health, _ = _read_latest()
    base = metrics.get("base", {})
    p99  = base.get("p99_ms", 0)
    stall = base.get("stall_flag", False)
    rev  = (health or {}).get("base_revert_ratio", 0.0)
    ts   = base.get("_ts", 0)

    # Data freshness check
    if ts and (time.time() - ts) > 30:
        return {"safe": False, "reason": "data_stale", "age_s": round(time.time() - ts)}

    if stall or p99 >= 5000:
        return {"safe": False, "reason": "sequencer_stall",  "base_p99_ms": p99, "revert_ratio": round(rev, 4)}
    if rev >= 0.30 or p99 > 500:
        return {"safe": False, "reason": "high_revert",      "base_p99_ms": p99, "revert_ratio": round(rev, 4)}
    if rev >= 0.10 or p99 > 200:
        return {"safe": False, "reason": "elevated_revert",  "base_p99_ms": p99, "revert_ratio": round(rev, 4)}

    return {"safe": True, "reason": "ok", "base_p99_ms": p99, "revert_ratio": round(rev, 4)}


@app.get("/v1/price", summary="Current x402 pricing (surge during MEV storms)", include_in_schema=True)
async def get_price(request: Request):
    # Silicon DNA: fingerprint paying agent (x402 already verified payment)
    _x_pay = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
    if _x_pay:
        try:
            from x402.http.utils import decode_payment_signature_header
            _pl = decode_payment_signature_header(_x_pay)
            _fa = (_pl.payload.get("authorization") or {}).get("from") or                   _pl.payload.get("from_address") or _pl.payload.get("from") or ""
            if _fa:
                _save_agent_fingerprint(_fa, str(request.url.path))
        except Exception:
            pass
    metrics, health, _ = _read_latest()
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
    _x_pay = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
    if _x_pay:
        try:
            from x402.http.utils import decode_payment_signature_header
            _pl = decode_payment_signature_header(_x_pay)
            _fa = (_pl.payload.get("authorization") or {}).get("from") or \
                  _pl.payload.get("from_address") or _pl.payload.get("from") or ""
            if _fa:
                _save_agent_fingerprint(_fa, str(request.url.path))
        except Exception:
            pass
    try:
        r = await _health_proof_client.get(_HEALTH_PROOF_URL)
        try:
            payload = r.json()
        except Exception:
            payload = {"raw": r.text}
        return JSONResponse(status_code=r.status_code, content=payload)
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "health_proof_upstream_error", "detail": str(e)})


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