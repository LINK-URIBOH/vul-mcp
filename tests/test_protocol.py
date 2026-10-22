import json
import logging
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from server import SERVICE_NAME, SERVICE_VERSION, create_app, public_origin

HEADERS = {
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
}


@pytest.fixture
def client():
    with TestClient(create_app(), base_url="https://vul.valna.cn", headers=HEADERS) as instance:
        yield instance


def rpc(client, method, params=None, request_id=1, headers=None):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return client.post("/mcp", json=payload, headers=headers)


@pytest.mark.parametrize("version", ["2025-03-26", "2025-06-18", "2025-11-25"])
def test_initialize_and_notification(client, version):
    response = rpc(client, "initialize", {
        "protocolVersion": version, "capabilities": {},
        "clientInfo": {"name": "regression-check", "version": "1.0"},
    }, headers={"MCP-Protocol-Version": version})
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["protocolVersion"] == version
    assert result["serverInfo"]["name"] == SERVICE_NAME
    assert result["serverInfo"]["version"] == SERVICE_VERSION
    assert "Mcp-Session-Id" not in response.headers
    notification = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert notification.status_code == 202


def test_tool_discovery(client):
    result = rpc(client, "tools/list").json()["result"]
    assert len(result["tools"]) == 1
    tool = result["tools"][0]
    assert tool["name"] == "health_check"
    assert tool["annotations"]["readOnlyHint"] is True
    assert tool["annotations"]["destructiveHint"] is False
    assert tool["annotations"]["openWorldHint"] is False
    assert tool["annotations"]["idempotentHint"] is True
    assert "marker" in tool["inputSchema"]["properties"]


@pytest.mark.parametrize("arguments,expected", [({}, None), ({"marker": None}, None),
    ({"marker": "cloud-20261022-0900"}, "cloud-20261022-0900"),
    ({"marker": "a" * 128}, "a" * 128)])
def test_health_result_and_audit(client, caplog, arguments, expected):
    with caplog.at_level(logging.INFO, logger=SERVICE_NAME):
        response = rpc(client, "tools/call", {"name": "health_check", "arguments": arguments})
    assert response.status_code == 200
    result = response.json()["result"]
    assert not result.get("isError", False)
    data = result["structuredContent"]
    assert set(data) == {"service_name", "service_version", "server_time_utc", "marker"}
    assert data["service_name"] == SERVICE_NAME
    assert data["service_version"] == SERVICE_VERSION
    assert data["marker"] == expected
    timestamp = datetime.fromisoformat(data["server_time_utc"].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - timestamp).total_seconds()) < 5
    events = [json.loads(record.message) for record in caplog.records if record.name == SERVICE_NAME]
    call = next(event for event in events if event["event"] == "health_check")
    assert call["result"] == data and call["outcome"] == "ok"
    assert any(event["event"] == "http_request" and event["status"] == 200 for event in events)


@pytest.mark.parametrize("marker", [123, True, [], {}, "", "a" * 129, "line\nbreak", "space here", "中文"])
def test_invalid_marker_rejected(client, marker, caplog):
    with caplog.at_level(logging.INFO, logger=SERVICE_NAME):
        response = rpc(client, "tools/call", {"name": "health_check", "arguments": {"marker": marker}})
    body = response.json()
    assert "error" in body or body.get("result", {}).get("isError") is True
    assert not any('"event": "health_check"' in record.message for record in caplog.records)


def test_unknown_tool_rejected(client):
    body = rpc(client, "tools/call", {"name": "run_command", "arguments": {}}).json()
    assert "error" in body or body.get("result", {}).get("isError") is True


def test_host_and_origin_checks(client):
    assert rpc(client, "tools/list", headers={"Host": "attacker.example"}).status_code == 421
    assert rpc(client, "tools/list", headers={"Origin": "https://attacker.example"}).status_code == 403
    assert rpc(client, "tools/list", headers={"Origin": "https://vul.valna.cn"}).status_code == 200


def test_local_host_allowed(client):
    assert rpc(client, "tools/list", headers={"Host": "127.0.0.1:8000"}).status_code == 200


def test_health_route(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/").status_code == 404


def test_request_body_limit(client):
    response = client.post("/mcp", content=b" " * (16 * 1024 + 1), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


@pytest.mark.parametrize("value", ["http://vul.valna.cn", "https://user:pass@vul.valna.cn",
    "https://vul.valna.cn/mcp", "https://vul.valna.cn?token=x", "https://vul.valna.cn#x"])
def test_invalid_public_origin(value):
    with pytest.raises(ValueError):
        public_origin(value)


def test_custom_public_origin(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://probe.example/")
    with TestClient(create_app(), base_url="https://probe.example", headers=HEADERS) as custom:
        assert rpc(custom, "tools/list").status_code == 200
        assert rpc(custom, "tools/list", headers={"Host": "vul.valna.cn"}).status_code == 421
