"""Authentication-gate tests for ``_require_api_key`` (src/app.py).

The smoke suite already parametrises every tool route with / without the
``X-API-Key`` header, but this module focuses specifically on the four
branches of ``_require_api_key``:

1. env var unset       -> auth disabled, request passes through
2. correct X-API-Key   -> request passes through
3. correct Bearer      -> request passes through (Security Copilot loader)
4. wrong / missing key -> 401
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from src.app import app

API_KEY = "auth-test-key"


@pytest.fixture()
def authed_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("MCP_SOC_PACK_API_KEY", API_KEY)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def open_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.delenv("MCP_SOC_PACK_API_KEY", raising=False)
    with TestClient(app) as c:
        yield c


def test_no_env_var_disables_auth(open_client: TestClient, mock_http) -> None:
    """When the env var is unset, every route must skip the gate (dev mode)."""
    import httpx

    mock_http(lambda r: httpx.Response(200, json={"vulnerabilities": []}))
    r = open_client.get("/kev/search", params={"limit": 1})
    assert r.status_code == 200


def test_x_api_key_header_accepted(authed_client: TestClient, mock_http) -> None:
    import httpx

    mock_http(lambda r: httpx.Response(200, json={"vulnerabilities": []}))
    r = authed_client.get(
        "/kev/search", params={"limit": 1}, headers={"X-API-Key": API_KEY}
    )
    assert r.status_code == 200


def test_bearer_token_accepted(authed_client: TestClient, mock_http) -> None:
    """Security Copilot's OpenAI plugin loader sends ``Authorization: Bearer``."""
    import httpx

    mock_http(lambda r: httpx.Response(200, json={"vulnerabilities": []}))
    r = authed_client.get(
        "/kev/search", params={"limit": 1}, headers={"Authorization": f"Bearer {API_KEY}"}
    )
    assert r.status_code == 200


def test_missing_header_returns_401(authed_client: TestClient) -> None:
    r = authed_client.get("/kev/search", params={"limit": 1})
    assert r.status_code == 401
    assert "API key" in r.json()["detail"]


def test_wrong_key_returns_401(authed_client: TestClient) -> None:
    r = authed_client.get(
        "/kev/search", params={"limit": 1}, headers={"X-API-Key": "wrong"}
    )
    assert r.status_code == 401


def test_wrong_bearer_returns_401(authed_client: TestClient) -> None:
    r = authed_client.get(
        "/kev/search", params={"limit": 1}, headers={"Authorization": "Bearer wrong"}
    )
    assert r.status_code == 401


def test_health_remains_public_with_auth_enabled(authed_client: TestClient) -> None:
    """``/health`` must stay un-authenticated for Container App probes."""
    r = authed_client.get("/health")
    assert r.status_code == 200


def test_openapi_remains_public_with_auth_enabled(authed_client: TestClient) -> None:
    """``/openapi.json`` must stay un-authenticated so SC can fetch the manifest."""
    r = authed_client.get("/openapi.json")
    assert r.status_code == 200
