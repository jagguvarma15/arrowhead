"""Load smoke test: drive the server concurrently and report latency.

This is a sanity check, not a benchmark: it confirms the server serves
many concurrent requests, the health endpoints stay green, and rate
limiting engages under a burst. Point it at a local stack where auth is
off (docker compose up), or pass a base URL.

    uv run python scripts/loadtest.py [BASE_URL] [TOTAL_CALLS]
"""

import asyncio
import json
import sys
import time

import httpx

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "calculate", "arguments": {"expression": "2 * (3 + 4)"}},
}
HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


async def one_call(client: httpx.AsyncClient, base: str) -> tuple[str, float]:
    start = time.perf_counter()
    try:
        response = await client.post(f"{base}/mcp", json=CALL, headers=HEADERS)
    except httpx.HTTPError:
        return "connection_error", (time.perf_counter() - start) * 1000
    elapsed_ms = (time.perf_counter() - start) * 1000
    if response.status_code != 200:
        return f"http_{response.status_code}", elapsed_ms
    result = _mcp_result(response).get("result", {})
    return ("refused" if result.get("isError") else "ok"), elapsed_ms


def _mcp_result(response: httpx.Response) -> dict:
    # The MCP endpoint returns JSON or Server-Sent Events depending on
    # configuration; handle both.
    if "application/json" in response.headers.get("content-type", ""):
        return response.json()
    for line in response.text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    return {}


async def main(base: str, total: int) -> int:
    async with httpx.AsyncClient(timeout=30) as client:
        for path in ("/health", "/ready"):
            response = await client.get(f"{base}{path}")
            print(f"{path}: {response.status_code} {response.json()}")
            if path == "/health" and response.status_code != 200:
                print("health check failed; aborting")
                return 1

        results = await asyncio.gather(
            *(one_call(client, base) for _ in range(total))
        )

    statuses = [status for status, _ in results]
    latencies = sorted(latency for _, latency in results)
    ok = statuses.count("ok")
    refused = statuses.count("refused")
    other = total - ok - refused

    print(f"\ncalls={total} ok={ok} rate_limited={refused} other={other}")
    print(
        f"latency ms: p50={_pct(latencies, 0.50):.1f} "
        f"p95={_pct(latencies, 0.95):.1f} max={latencies[-1]:.1f}"
    )
    if refused == 0:
        print(
            "note: no rate-limit refusals seen; increase TOTAL_CALLS or lower "
            "ARROWHEAD_CALCULATE_PER_MINUTE to exercise limiting"
        )
    return 0 if other == 0 else 1


def _pct(sorted_values: list[float], fraction: float) -> float:
    index = min(len(sorted_values) - 1, int(len(sorted_values) * fraction))
    return sorted_values[index]


if __name__ == "__main__":
    base_url = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip(
        "/"
    )
    total_calls = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    raise SystemExit(asyncio.run(main(base_url, total_calls)))
