"""Run with the project environment or inside the container; exits nonzero on failure."""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from uuid import uuid4

from mcp import Client


async def probe(url: str, marker: str) -> dict:
    async with Client(url, read_timeout_seconds=15) as client:
        tools = await client.list_tools()
        assert [tool.name for tool in tools.tools] == ["health_check"], "Unexpected tool list"
        annotations = tools.tools[0].annotations
        assert annotations and annotations.read_only_hint is True, "Missing read-only hint"
        result = await client.call_tool("health_check", {"marker": marker})
        assert not result.is_error, "health_check returned an error"
        data = result.structured_content
        assert isinstance(data, dict), "Missing structured result"
        assert set(data) == {"service_name", "service_version", "server_time_utc", "marker"}
        assert data["service_name"] == "vul-mcp-check"
        assert data["service_version"] == "0.1.0"
        assert data["marker"] == marker, "Marker does not match"
        timestamp = datetime.fromisoformat(data["server_time_utc"].replace("Z", "+00:00"))
        assert timestamp.utcoffset().total_seconds() == 0, "Expected UTC timestamp"
        assert abs((datetime.now(timezone.utc) - timestamp).total_seconds()) < 120, "Server clock differs by >120 seconds"
        # In v2, argument validation is a JSON-RPC error rather than necessarily isError.
        rejected = False
        try:
            invalid = await client.call_tool("health_check", {"marker": 123})
            rejected = bool(invalid.is_error)
        except Exception as exc:
            if getattr(exc, "error", None) is not None or "validation" in str(exc).lower():
                rejected = True
            else:
                raise
        assert rejected, "Invalid marker type was accepted"
        return {"probe": "passed", "tools": ["health_check"], "result": data,
                "invalid_marker_rejected": True}


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP connectivity and read-only tool probe")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--marker", default=f"probe-{uuid4().hex}")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(probe(args.url, args.marker)), ensure_ascii=False, indent=2))
    except Exception as exc:
        print(f"Probe failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
