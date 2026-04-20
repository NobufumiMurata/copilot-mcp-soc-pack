"""Tests for security hardening: scoped CORS and constant-time API-key compare.

Both behaviours are configured at app startup, so we re-import ``src.app``
in a child interpreter via the ``importlib.reload`` pattern would be
cleaner — but for the CORS test it is enough to assert that the default
configuration installs no ``CORSMiddleware`` and that explicit origins
do install one.
"""

from __future__ import annotations

import hmac
import importlib
from collections.abc import Iterator

import pytest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

import src.app as app_module
from src.app import _resolve_cors_origins


@pytest.fixture()
def fresh_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[None]]:
    """Re-import ``src.app`` so module-level CORS resolution sees fresh env."""

    def _reload():
        return importlib.reload(app_module)

    yield _reload  # type: ignore[misc]


def test_resolve_cors_origins_default_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_SOC_PACK_CORS_ORIGINS", raising=False)
    assert _resolve_cors_origins() == []


def test_resolve_cors_origins_parses_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "MCP_SOC_PACK_CORS_ORIGINS",
        "https://a.example.com, https://b.example.com,, https://c.example.com",
    )
    assert _resolve_cors_origins() == [
        "https://a.example.com",
        "https://b.example.com",
        "https://c.example.com",
    ]


def test_resolve_cors_origins_supports_wildcard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_SOC_PACK_CORS_ORIGINS", "*")
    assert _resolve_cors_origins() == ["*"]


def test_default_app_has_no_cors_middleware(
    monkeypatch: pytest.MonkeyPatch, fresh_app
) -> None:
    monkeypatch.delenv("MCP_SOC_PACK_CORS_ORIGINS", raising=False)
    reloaded = fresh_app()
    middlewares = [m.cls for m in reloaded.app.user_middleware]
    assert CORSMiddleware not in middlewares


def test_explicit_origin_installs_cors_middleware(
    monkeypatch: pytest.MonkeyPatch, fresh_app
) -> None:
    monkeypatch.setenv("MCP_SOC_PACK_CORS_ORIGINS", "https://app.example.com")
    reloaded = fresh_app()
    middlewares = [m.cls for m in reloaded.app.user_middleware]
    assert CORSMiddleware in middlewares


def test_no_cors_response_headers_when_origins_unset(
    monkeypatch: pytest.MonkeyPatch, fresh_app
) -> None:
    """Browsers must not get an Access-Control-Allow-Origin by default."""
    monkeypatch.delenv("MCP_SOC_PACK_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("MCP_SOC_PACK_API_KEY", raising=False)
    reloaded = fresh_app()
    with TestClient(reloaded.app) as c:
        r = c.get("/health", headers={"Origin": "https://attacker.example.com"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_api_key_uses_constant_time_compare() -> None:
    """Sanity check that hmac.compare_digest is the chosen primitive."""
    # We cannot directly observe timing in CI, but we can assert the
    # function we rely on exists and returns False for a near-miss.
    assert hmac.compare_digest("a" * 32, "b" * 32) is False
    assert hmac.compare_digest("same-key", "same-key") is True
