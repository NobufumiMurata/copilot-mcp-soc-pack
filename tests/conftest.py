"""Shared pytest fixtures for the test suite.

Centralises two concerns that every test file would otherwise duplicate:

1. **Reset the shared httpx.AsyncClient between tests.** The module-level
   client in ``src.common.http`` is bound to the first asyncio event loop
   that touches it. ``TestClient`` and direct ``asyncio.run`` calls each
   spin up fresh loops, so the cached singleton must be cleared or the
   second test hits ``RuntimeError: Event loop is closed``.

2. **``mock_http`` factory** that swaps the shared client for an
   ``httpx.AsyncClient`` backed by ``MockTransport``. Tests pass a handler
   ``(httpx.Request) -> httpx.Response`` and the rest of the codebase
   uses the mock transparently via ``get_client()``.

The factory also resets every per-tool ``TTLCache`` so each test starts
from a clean cache state.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

# IMPORTANT: set the per-tool API-key env vars BEFORE importing src.app
# (transitively imported via src.common). The app uses presence of these
# env vars to decide whether to register the corresponding tool routers,
# so the test suite must opt-in to the full surface.
for _env_var in (
    "GREYNOISE_API_KEY",
    "ABUSEIPDB_API_KEY",
    "ABUSE_CH_AUTH_KEY",
    "OTX_API_KEY",
):
    os.environ.setdefault(_env_var, "test-fixture-key")

from src import common  # noqa: E402
from src.common import http as http_module  # noqa: E402
from src.tools import (  # noqa: E402
    abusech,
    abuseipdb,
    attack,
    circl_hashlookup,
    crtsh,
    d3fend,
    epss,
    greynoise,
    hibp,
    kev,
    osv,
    otx,
    ransomwarelive,
)

# Every tool module owns its own _cache instance; we reset all of them so
# tests do not leak responses to each other.
_ALL_CACHES = [
    abusech._cache,
    abuseipdb._cache,
    attack._cache,
    circl_hashlookup._cache,
    crtsh._cache,
    epss._cache,
    greynoise._cache,
    hibp._cache,
    kev._cache,
    osv._query_cache,
    osv._vuln_cache,
    otx._cache,
    ransomwarelive._cache,
]


@pytest.fixture(autouse=True)
def _reset_shared_http_client() -> Iterator[None]:
    """Clear the shared httpx client and every TTL cache before/after each test."""
    common.http._client = None  # type: ignore[attr-defined]
    for cache in _ALL_CACHES:
        cache._store.clear()  # type: ignore[attr-defined]
    _reset_d3fend_state()
    yield
    common.http._client = None  # type: ignore[attr-defined]
    for cache in _ALL_CACHES:
        cache._store.clear()  # type: ignore[attr-defined]
    _reset_d3fend_state()


def _reset_d3fend_state() -> None:
    d3fend._state["loaded_at"] = 0.0
    d3fend._state["by_attack"] = {}
    d3fend._state["by_defense"] = {}


@pytest.fixture()
def mock_http() -> Iterator[Callable[[Callable[[httpx.Request], httpx.Response]], None]]:
    """Replace the shared httpx.AsyncClient with one backed by MockTransport.

    Usage::

        def test_thing(mock_http):
            def handler(request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, json={"ok": True})
            mock_http(handler)
            # ... call the helper under test ...
    """

    def _install(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        http_module._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={"User-Agent": "copilot-mcp-soc-pack-tests/1.0"},
        )

    yield _install


def make_response(
    status_code: int = 200,
    json_body: Any = None,
    text: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Tiny convenience for building ``httpx.Response`` objects in tests."""
    if json_body is not None:
        return httpx.Response(status_code, json=json_body, headers=headers)
    return httpx.Response(status_code, text=text or "", headers=headers)
