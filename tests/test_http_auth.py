"""Bearer auth for the HTTP transport: fail-closed, constant-time, no token leaks."""
import logging

import pytest
from starlette.testclient import TestClient

import coach.http_auth as http_auth
import coach.server as server

TOKEN = "t" * 8 + "-correct-horse-battery-staple"


@pytest.fixture
def client():
    app = server.mcp.http_app(middleware=http_auth.build_middleware(TOKEN))
    with TestClient(app) as c:
        yield c


INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-03-26", "capabilities": {},
               "clientInfo": {"name": "t", "version": "0"}},
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream",
               "Content-Type": "application/json"}


def test_missing_token_is_401(client):
    r = client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


def test_wrong_token_is_401(client):
    r = client.post("/mcp", json=INIT,
                    headers={**MCP_HEADERS, "Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_wrong_scheme_is_401(client):
    r = client.post("/mcp", json=INIT,
                    headers={**MCP_HEADERS, "Authorization": f"Basic {TOKEN}"})
    assert r.status_code == 401


def test_correct_token_reaches_mcp(client):
    r = client.post("/mcp", json=INIT,
                    headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200


def test_health_is_public_and_static(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_health_exemption_is_exact(client):
    assert client.get("/health/anything").status_code == 401
    assert client.post("/health", json={}).status_code == 401


def test_comparison_is_constant_time(monkeypatch):
    calls = []
    real = http_auth.hmac.compare_digest
    monkeypatch.setattr(http_auth.hmac, "compare_digest",
                        lambda a, b: calls.append(1) or real(a, b))
    app = server.mcp.http_app(middleware=http_auth.build_middleware(TOKEN))
    with TestClient(app) as c:
        c.post("/mcp", json=INIT, headers={**MCP_HEADERS, "Authorization": "Bearer x"})
    assert calls


@pytest.mark.parametrize("env", [{}, {"MCP_AUTH_TOKEN": ""}, {"MCP_AUTH_TOKEN": "   "},
                                 {"MCP_AUTH_TOKEN": "short"}])
def test_require_token_fails_closed(env):
    with pytest.raises(http_auth.AuthConfigError) as exc:
        http_auth.require_token(env)
    assert "MCP_AUTH_TOKEN" in str(exc.value)


@pytest.mark.parametrize("transport", ["http", "streamable-http", "sse"])
def test_main_refuses_http_without_token(monkeypatch, capsys, transport):
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("COACH_TRANSPORT", transport)
    monkeypatch.setattr(server, "check_setup", lambda: True)
    ran = []
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: ran.append((a, k)))
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 2
    assert not ran, "server must not start without a token"
    assert "MCP_AUTH_TOKEN" in capsys.readouterr().err


def test_main_http_with_token_installs_middleware(monkeypatch):
    monkeypatch.setenv("MCP_AUTH_TOKEN", TOKEN)
    monkeypatch.setenv("COACH_TRANSPORT", "streamable-http")
    monkeypatch.setattr(server, "check_setup", lambda: True)
    ran = []
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: ran.append((a, k)))
    server.main()
    (_, kwargs), = ran
    assert kwargs["transport"] == "streamable-http"
    assert kwargs["middleware"][0].cls is http_auth.BearerAuthMiddleware


def test_stdio_untouched(monkeypatch):
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("COACH_TRANSPORT", raising=False)
    monkeypatch.setattr(server, "check_setup", lambda: True)
    ran = []
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: ran.append((a, k)))
    server.main()
    assert ran == [((), {"transport": "stdio"})]


def test_token_never_logged(client, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    client.post("/mcp", json=INIT, headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}x"})
    client.post("/mcp", json=INIT, headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})
    client.post("/mcp", json=INIT, headers=MCP_HEADERS)
    out = capsys.readouterr()
    blob = caplog.text + out.out + out.err
    assert TOKEN not in blob
    assert "Rejected unauthenticated request" in caplog.text


def test_startup_error_does_not_contain_token(monkeypatch, capsys):
    monkeypatch.setenv("MCP_AUTH_TOKEN", "short-secret")
    monkeypatch.setenv("COACH_TRANSPORT", "http")
    monkeypatch.setattr(server, "check_setup", lambda: True)
    with pytest.raises(SystemExit):
        server.main()
    assert "short-secret" not in capsys.readouterr().err
