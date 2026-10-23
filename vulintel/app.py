import asyncio
import contextlib
import logging
import httpx
from pathlib import Path

from sqlalchemy import text
from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .auth import Verifier
from .config import settings
from .db import migrate, session
from .mcp_app import make_mcp
from .sources import seed_sources
from .web import routes


def initialize():
    migrate()
    with session() as db:
        if db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(86221024)"))
        seed_sources(db)


def create_app():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("vulintel").setLevel(logging.INFO)
    for name in ("httpx", "httpx2", "httpcore", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)
    cfg = settings()
    verifier = Verifier(cfg)
    mcp = make_mcp(verifier)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        await asyncio.to_thread(initialize)
        async with mcp.router.lifespan_context(mcp):
            yield

    async def health(request):
        def ping():
            with session() as db:
                db.execute(text("SELECT 1"))
        try:
            await asyncio.to_thread(ping)
            return JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)

    async def root(request):
        return RedirectResponse("/admin/", status_code=303)

    async def metadata(request):
        return JSONResponse({"resource": cfg.resource_url, "authorization_servers": [cfg.issuer_url],
                             "scopes_supported": ["vul.read", "vul.submit", "vul.deliver", "offline_access"],
                             "bearer_methods_supported": ["header"]})

    async def authorization_metadata(request):
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(cfg.keycloak_internal_url + "/.well-known/openid-configuration")
            response.raise_for_status()
            document = response.json()
        if document.get("issuer") != cfg.issuer_url:
            return JSONResponse({"error": "Keycloak issuer mismatch"}, status_code=503)
        return JSONResponse(document)

    async def internal_error(request, exc):
        logging.getLogger("vulintel").error("request_failed type=%s", type(exc).__name__)
        return JSONResponse({"error": "服务器处理失败，请检查运行状态"}, status_code=500)

    app = Starlette(routes=[Route("/", root), Route("/healthz", health),
                            Route("/.well-known/oauth-protected-resource/mcp", metadata),
                            Route("/.well-known/oauth-protected-resource", metadata), *routes(),
                            Route("/.well-known/oauth-authorization-server/auth/realms/vul", authorization_metadata),
                            Route("/.well-known/openid-configuration/auth/realms/vul", authorization_metadata),
                            Mount("/static", StaticFiles(directory=Path(__file__).parent / "static")),
                            Mount("/", mcp)], lifespan=lifespan, exception_handlers={500: internal_error})
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=[cfg.public_base_url.split("//")[1], "127.0.0.1", "localhost"])
    app.state.verifier = verifier
    return app
