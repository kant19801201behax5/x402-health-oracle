"""Phoenix Zero RPC Gateway — transparent health-checking proxy.

Sits between an agent and an upstream L2 RPC.
Before forwarding eth_sendRawTransaction (and other write methods),
checks Phoenix health oracle. If DEGRADED or FAIL — returns warning
or rejects with a suggestion to use a healthier chain.

Usage:
    uvicorn gateway.rpc_gateway:app --host 0.0.0.0 --port 3003
"""

import time
import json
import logging
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger("phoenix.rpc_gateway")

app = FastAPI(title="Phoenix RPC Gateway", version="1.0.0")

UPSTREAM_RPCS: dict[str, str] = {
    "base": "https://mainnet.base.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "zksync": "https://mainnet.era.zksync.io",
    "scroll": "https://rpc.scroll.io",
    "mantle": "https://rpc.mantle.xyz",
    "linea": "https://rpc.linea.build",
    "blast": "https://rpc.blast.io",
    "mode": "https://mainnet.mode.network",
    "taiko": "https://rpc.mainnet.taiko.xyz",
    "polygon_zkevm": "https://zkevm-rpc.com",
}

PHOENIX_API = "https://rtt.phoenix-ai.work"

WRITE_METHODS = {
    "eth_sendRawTransaction",
    "eth_sendTransaction",
}

_health_cache: dict[str, Any] = {"data": None, "ts": 0}
CACHE_TTL = 5


async def _get_health() -> dict[str, Any]:
    now = time.time()
    if _health_cache["data"] and (now - _health_cache["ts"]) < CACHE_TTL:
        return _health_cache["data"]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{PHOENIX_API}/api/health")
            data = r.json()
            _health_cache["data"] = data
            _health_cache["ts"] = now
            return data
    except Exception as e:
        logger.warning("Phoenix health check failed: %s", e)
        return {"health": "unknown", "safe": True, "last_measurement_s": 0}


def _derive_verdict(data: dict) -> tuple[str, str]:
    if data.get("health") != "operational":
        return "FAIL", f"service {data.get('health', 'unknown')}"
    if data.get("last_measurement_s", 0) > 30:
        return "DEGRADED", f"stale data: {data['last_measurement_s']}s ago"
    if not data.get("safe", True):
        return "FAIL", "unsafe conditions detected"
    return "PASS", "ok"


@app.get("/")
async def root():
    return {
        "service": "Phoenix RPC Gateway",
        "chains": list(UPSTREAM_RPCS.keys()),
        "health_source": PHOENIX_API,
    }


@app.post("/rpc/{chain}")
async def rpc_proxy(chain: str, request: Request):
    if chain not in UPSTREAM_RPCS:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": f"Unknown chain: {chain}. Supported: {', '.join(sorted(UPSTREAM_RPCS))}"},
                "id": None,
            },
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
        )

    method = body.get("method", "")
    health = await _get_health()
    verdict, reason = _derive_verdict(health)

    if method in WRITE_METHODS and verdict == "FAIL":
        return JSONResponse(
            status_code=503,
            content={
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Phoenix health check FAIL: {reason}. Transaction blocked to protect funds.",
                    "data": {
                        "verdict": verdict,
                        "reason": reason,
                        "suggestion": "Try a different chain or wait for recovery.",
                        "health_source": PHOENIX_API,
                    },
                },
                "id": body.get("id"),
            },
            headers={"X-Phoenix-Health": verdict, "X-Phoenix-Reason": reason},
        )

    async with httpx.AsyncClient(timeout=30) as client:
        upstream = UPSTREAM_RPCS[chain]
        r = await client.post(
            upstream,
            json=body,
            headers={"Content-Type": "application/json"},
        )

    headers = {
        "X-Phoenix-Health": verdict,
        "X-Phoenix-Reason": reason,
        "X-Phoenix-Source": PHOENIX_API,
    }

    if method in WRITE_METHODS and verdict == "DEGRADED":
        headers["X-Phoenix-Warning"] = f"Network degraded: {reason}"

    return Response(
        content=r.content,
        status_code=r.status_code,
        media_type="application/json",
        headers=headers,
    )
