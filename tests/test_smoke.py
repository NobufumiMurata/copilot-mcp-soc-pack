"""Smoke test that walks every registered route with a TestClient.

This is a *contract* check, not a live integration test:
- Endpoints behind ``_require_api_key`` must answer 401 without a header
  and not 401 (i.e. 200 / 422 / 503) with the correct header.
- Endpoints that require an external API key (abuse.ch, GreyNoise,
  AbuseIPDB) are allowed to return 503 when the key is unset; we still
  exercise them so the routing stays wired.

The goal is to catch regressions where a refactor accidentally drops a
route from the OpenAPI surface or breaks the auth gate.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from src import common
from src.app import app

API_KEY = "smoke-test-key"


@pytest.fixture(autouse=True)
def _reset_shared_http_client() -> Iterator[None]:
    """The module-level httpx.AsyncClient gets bound to the first event loop.

    TestClient spins up a fresh loop per test, so the cached singleton must
    be cleared between tests or the second one hits ``Event loop is closed``.
    """
    common.http._client = None  # type: ignore[attr-defined]
    yield
    common.http._client = None  # type: ignore[attr-defined]


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("MCP_SOC_PACK_API_KEY", API_KEY)
    # Force abuse.ch / GreyNoise / AbuseIPDB into the 503 branch so the
    # smoke test stays hermetic (no outbound network to upstream APIs).
    for var in ("ABUSE_CH_AUTH_KEY", "GREYNOISE_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    with TestClient(app) as c:
        yield c


def _interesting_routes() -> list[tuple[str, str]]:
    """Return (method, path) for every API GET route under a tool router."""
    routes: list[tuple[str, str]] = []
    for r in app.routes:
        path = getattr(r, "path", "")
        methods = getattr(r, "methods", set()) or set()
        if "GET" not in methods:
            continue
        if path in {"/", "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}:
            continue
        # Skip parametrised paths; they need real values to pass validation.
        if "{" in path:
            continue
        routes.append(("GET", path))
    return routes


def test_health_is_public(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_openapi_is_public(client: TestClient) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["openapi"] == "3.0.1"
    assert "paths" in spec and len(spec["paths"]) >= 15


@pytest.mark.parametrize("method,path", _interesting_routes())
def test_route_requires_api_key(client: TestClient, method: str, path: str) -> None:
    """Every tool route must reject unauthenticated callers."""
    if path == "/health":
        pytest.skip("health is intentionally public")
    r = client.request(method, path)
    assert r.status_code == 401, f"{path} returned {r.status_code} without API key"


@pytest.mark.parametrize("method,path", _interesting_routes())
def test_route_accepts_api_key(client: TestClient, method: str, path: str) -> None:
    """With the right key the gate must let the request through.

    Downstream behaviour (200, 422 missing query param, 503 missing
    upstream key) is fine; the only forbidden response is 401.
    """
    r = client.request(method, path, headers={"X-API-Key": API_KEY})
    assert r.status_code != 401, f"{path} still 401 with API key"
    assert r.status_code in (200, 400, 404, 422, 502, 503), (
        f"{path} unexpected status {r.status_code}: {r.text[:200]}"
    )


def test_api_key_env_default_disables_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the env var is unset, every route should be reachable without a key."""
    monkeypatch.delenv("MCP_SOC_PACK_API_KEY", raising=False)
    # Re-import not needed; _require_api_key reads the env on every request.
    with TestClient(app) as c:
        r = c.get("/kev/lookup", params={"cve_id": "CVE-2024-3400"})
    # Either 200 (cache hit) or 502/503 if upstream is unreachable in CI; the
    # important check is "not 401".
    assert r.status_code != 401
    assert os.environ.get("MCP_SOC_PACK_API_KEY") is None
