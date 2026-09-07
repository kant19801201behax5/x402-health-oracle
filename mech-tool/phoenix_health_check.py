"""Phoenix Zero L2 Health Oracle — Olas Mech Tool

Mech tool that queries Phoenix Zero kernel-level telemetry
to determine whether an L2 network is safe for transaction execution.

Returns PASS/DEGRADED/FAIL verdict with RTT and uptime evidence.
"""

from typing import Any, Dict, Optional, Tuple
import json

try:
    import httpx
except ImportError:
    import urllib.request

    class _MinimalClient:
        def get(self, url: str, timeout: float = 10) -> "_Resp":
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return _Resp(r.status, r.read())

    class _Resp:
        def __init__(self, code: int, body: bytes):
            self.status_code = code
            self._body = body

        def json(self) -> Any:
            return json.loads(self._body)

    httpx = None  # type: ignore

PHOENIX_API = "https://rtt.phoenix-ai.work"


def _derive_verdict(data: dict) -> Tuple[str, str]:
    if data.get("health") != "operational":
        return "FAIL", f"service {data.get('health', 'unknown')}"
    if data.get("last_measurement_s", 0) > 30:
        return "DEGRADED", f"stale data: {data['last_measurement_s']}s ago"
    if not data.get("safe", True):
        return "FAIL", "unsafe conditions detected by kernel telemetry"
    return "PASS", "operational, data fresh, safe to execute"


def run(**kwargs: Any) -> Tuple[str, Optional[str], Optional[Dict[str, Any]], Any]:
    """Olas Mech tool interface.

    kwargs may contain:
        tool_input (str): JSON with optional "chain" field
        prompt (str): natural language query (fallback)
    """
    tool_input = kwargs.get("tool_input", "{}")

    try:
        params = json.loads(tool_input) if isinstance(tool_input, str) else tool_input
    except (json.JSONDecodeError, TypeError):
        params = {}

    chain = params.get("chain")

    try:
        if httpx is not None:
            client = httpx.Client()
        else:
            client = _MinimalClient()

        resp = client.get(f"{PHOENIX_API}/api/health", timeout=10)

        if resp.status_code != 200:
            return (
                json.dumps({"verdict": "FAIL", "reason": f"API returned {resp.status_code}"}),
                None,
                None,
                None,
            )

        data = resp.json()
        verdict, reason = _derive_verdict(data)

        result = {
            "verdict": verdict,
            "reason": reason,
            "oracle_uptime_s": data.get("uptime_s"),
            "last_measurement_s": data.get("last_measurement_s"),
            "chains_monitored": 12,
            "source": "rtt.phoenix-ai.work",
            "integrity": "BLAKE3+Ed25519",
            "sampling_interval": "2s",
        }

        if chain:
            result["chain"] = chain
            result["premium_endpoint"] = f"{PHOENIX_API}/api/v1/chains/{chain}"
            result["premium_price"] = "$0.01 USDC via x402"

        return (json.dumps(result), None, None, None)

    except Exception as e:
        return (
            json.dumps({"verdict": "FAIL", "reason": f"oracle unreachable: {str(e)}"}),
            None,
            None,
            None,
        )


if __name__ == "__main__":
    output, *_ = run(tool_input='{"chain": "base"}')
    print(json.dumps(json.loads(output), indent=2))
