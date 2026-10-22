"""Public, read-only MCP connectivity probe; no business capabilities."""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Annotated, Literal
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ToolAnnotations
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse
from starlette.routing import Route

SERVICE_NAME = "vul-mcp-check"
SERVICE_VERSION = "0.1.0"
MARKER_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
logger = logging.getLogger(SERVICE_NAME)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def audit(event: str, **fields: object) -> None:
    logger.info(json.dumps({"timestamp_utc": utc_now(), "event": event, **fields}, ensure_ascii=True))


def public_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.port not in (None, 443)
        or ":" in parsed.hostname
    ):
        raise ValueError("PUBLIC_BASE_URL must be an HTTPS origin, e.g. https://vul.valna.cn")
    return f"https://{parsed.hostname}"


class HealthResult(BaseModel):
    service_name: Literal["vul-mcp-check"] = SERVICE_NAME
    service_version: Literal["0.1.0"] = SERVICE_VERSION
    server_time_utc: str
    marker: str | None


class RequestAudit:
    """Log request completion without recording headers, IPs or request bodies."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = time.monotonic()
        status = 500

        async def observe(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, observe)
        finally:
            if scope["path"] == "/mcp":
                audit("http_request", method=scope["method"], path="/mcp", status=status,
                      duration_ms=round((time.monotonic() - started) * 1000, 2))


def create_app():
    origin = public_origin(os.environ.get("PUBLIC_BASE_URL", "https://vul.valna.cn"))
    hostname = urlsplit(origin).hostname
    mcp = MCPServer(
        SERVICE_NAME,
        version=SERVICE_VERSION,
        instructions="Public read-only connectivity test. Only health_check is available.",
        subscriptions=False,
    )

    @mcp.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False,
            idempotent_hint=True, open_world_hint=False,
        ),
    )
    async def health_check(
        marker: Annotated[
            str | None,
            Field(strict=True, max_length=128, pattern=MARKER_PATTERN,
                  description="Optional public correlation marker: 1-128 ASCII letters, digits, . _ : -"),
        ] = None,
    ) -> HealthResult:
        """Return a public service identifier, UTC time and the unchanged marker. Do not send secrets."""
        result = HealthResult(server_time_utc=utc_now(), marker=marker)
        audit("health_check", outcome="ok", result=result.model_dump())
        return result

    app = mcp.streamable_http_app(
        streamable_http_path="/mcp", json_response=True, stateless_http=True,
        max_request_body_size=16 * 1024,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[hostname, f"{hostname}:443", "127.0.0.1:*", "localhost:*"],
            allowed_origins=[origin, f"{origin}:443", "http://127.0.0.1:*", "http://localhost:*"],
        ),
    )

    async def healthz(request):
        return JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})

    app.routes.append(Route("/healthz", healthz, methods=["GET"]))
    app.add_middleware(RequestAudit)
    return app


def main() -> None:
    import uvicorn

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    uvicorn.run(create_app(), host="0.0.0.0", port=8000, access_log=False,
                proxy_headers=False, log_level="warning")


if __name__ == "__main__":
    main()
