import secrets
import time
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

from vulintel.app import create_app
from vulintel.auth import Verifier, token_hash
from vulintel.config import settings
from vulintel.db import Source, WebSession, now
from vulintel.mcp_app import principal


@pytest.fixture
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, **override):
    cfg = settings()
    payload = {"iss": cfg.issuer_url, "sub": "admin-sub", "aud": cfg.resource_url,
               "iat": int(time.time()), "exp": int(time.time()) + 300, "azp": cfg.mcp_client_id,
               "scope": "vul.read vul.submit vul.deliver",
               "realm_access": {"roles": ["vul-admin"]}, **override}
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": "test-key"})


@pytest.mark.parametrize("override,valid", [({}, True), ({"aud": "other-service"}, False),
    ({"iss": "https://evil.example"}, False), ({"exp": int(time.time()) - 100}, False),
    ({"azp": "other-client"}, False), ({"realm_access": {"roles": []}}, False)])
async def test_token_signature_audience_issuer_expiry_and_role(store, key, override, valid):
    verifier = Verifier()
    verifier.keys = {"test-key": key.public_key()}
    verifier.loaded = time.monotonic()
    assert bool(await verifier.verify_token(token(key, **override))) is valid


async def test_wrong_signature_rejected(store, key):
    verifier = Verifier()
    verifier.keys = {"test-key": rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()}
    verifier.loaded = time.monotonic()
    assert await verifier.verify_token(token(key)) is None


def test_scope_not_escalated():
    info = AccessToken(token="test", client_id="vul-mcp", subject="admin", scopes=["vul.read"])
    reset = auth_context_var.set(AuthenticatedUser(info))
    try:
        assert principal("vul.read") == "admin"
        with pytest.raises(PermissionError):
            principal("vul.deliver")
    finally:
        auth_context_var.reset(reset)


def test_authenticated_mcp_tools_and_metadata(store, key):
    app = create_app()
    app.state.verifier.keys = {"test-key": key.public_key()}
    app.state.verifier.loaded = time.monotonic()
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
    with TestClient(app, base_url="https://vul.valna.cn", headers=headers) as client:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        result = client.post("/mcp", json=payload)
        assert result.status_code == 401 and "resource_metadata" in result.headers["WWW-Authenticate"]
        metadata = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert metadata["scopes_supported"] == ["vul.read", "vul.submit", "vul.deliver", "offline_access"]
        auth = {"Authorization": "Bearer " + token(key)}
        response = client.post("/mcp", json=payload, headers=auth)
        assert response.status_code == 200, response.text
        tools = {t["name"]: t for t in response.json()["result"]["tools"]}
        assert len(tools) == 7
        assert tools["health_check"]["annotations"]["readOnlyHint"]
        assert tools["finalize_report"]["annotations"]["readOnlyHint"] is False
        assert tools["finalize_report"]["annotations"]["openWorldHint"] is True
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "health_check", "arguments": {"marker": "auth-test-01"}}}, headers=auth)
        assert response.json()["result"].get("structuredContent", {}).get("marker") == "auth-test-01", response.text
        readonly = {"Authorization": "Bearer " + token(key, scope="vul.read")}
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "open_report_batch", "arguments": {}}}, headers=readonly)
        body = response.json()
        assert "error" in body or body.get("result", {}).get("isError")


def test_web_login_guard_csrf_and_toggle(store):
    app = create_app()
    with TestClient(app, base_url="https://vul.valna.cn", follow_redirects=False) as client:
        assert client.get("/admin/").status_code == 303
        assert client.get("/admin/sources").headers["location"] == "/admin/login"
        raw = secrets.token_urlsafe(32)
        with store() as db:
            db.add(WebSession(id=token_hash(raw), subject="test-admin", csrf="correct",
                              expires=now() + timedelta(minutes=10)))
            db.commit()
        client.cookies.set("vul_session", raw)
        assert client.get("/admin/").status_code == 200
        for route in ["vulnerabilities", "reports", "sources", "tasks", "deliveries"]:
            result = client.get("/admin/" + route)
            assert result.status_code == 200, result.text
            assert "Content-Security-Policy" in result.headers
        path = "/admin/actions/source/nvd/toggle"
        assert client.post(path, data={"csrf": "wrong"}).status_code == 403
        assert client.post(path, data={"csrf": "correct"}).status_code == 303
        with store() as db:
            assert db.get(Source, "nvd").enabled is False
        assert client.get("/admin/callback?state=forged&code=x").status_code == 400
        assert client.get("/admin/login").status_code == 307
        assert "code_challenge_method=S256" in client.get("/admin/login").headers["location"]


def test_web_escape_filters_and_expired_session(store):
    from vulintel.db import Vulnerability
    with store() as db:
        db.add(Vulnerability(title="<script>alert(1)</script>", data={"aliases": ["CVE-test"]},
                             product="Node.js", severity="high", exploited=True))
        raw = secrets.token_urlsafe(32)
        db.add(WebSession(id=token_hash(raw), subject="test", csrf="correct", expires=now() + timedelta(minutes=1)))
        db.commit()
    with TestClient(create_app(), base_url="https://vul.valna.cn", follow_redirects=False) as client:
        client.cookies.set("vul_session", raw)
        result = client.get("/admin/vulnerabilities?product=Node.js&severity=high&exploited=yes")
        assert result.status_code == 200
        assert "&lt;script&gt;" in result.text and "<script>" not in result.text
        assert client.get("/admin/vulnerabilities?since=broken").status_code == 400
        with store() as db:
            db.get(WebSession, token_hash(raw)).expires = now() - timedelta(seconds=1)
            db.commit()
        assert client.get("/admin/").status_code == 303
