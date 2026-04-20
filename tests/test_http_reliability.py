"""Tests for reliability primitives in src/common/http.py."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from src.common import http as http_module
from src.common.http import (
    DEFAULT_CACHE_MAX_ENTRIES,
    TTLCache,
    request_with_retry,
)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- request_with_retry ----------------------------------------------------


def _install_handler_chain(responses: list[httpx.Response]) -> list[httpx.Request]:
    """Install a MockTransport that returns ``responses`` in order, recording requests."""
    seen: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if queue:
            return queue.pop(0)
        return httpx.Response(200, json={"final": True})

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return seen


def test_retry_recovers_after_transient_5xx():
    seen = _install_handler_chain(
        [
            httpx.Response(503),
            httpx.Response(502),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    response = _run(
        request_with_retry("GET", "https://example.test/x", max_retries=3, backoff_base=0.0)
    )
    assert response.status_code == 200
    assert len(seen) == 3


def test_retry_returns_last_response_when_exhausted():
    seen = _install_handler_chain(
        [httpx.Response(503), httpx.Response(503), httpx.Response(503)]
    )
    response = _run(
        request_with_retry("GET", "https://example.test/x", max_retries=2, backoff_base=0.0)
    )
    assert response.status_code == 503
    assert len(seen) == 3  # 1 initial + 2 retries


def test_retry_does_not_retry_4xx_other_than_408_425_429():
    seen = _install_handler_chain([httpx.Response(404)])
    response = _run(
        request_with_retry("GET", "https://example.test/x", max_retries=3, backoff_base=0.0)
    )
    assert response.status_code == 404
    assert len(seen) == 1  # no retry


def test_retry_honours_429():
    seen = _install_handler_chain([httpx.Response(429), httpx.Response(200, json={"ok": True})])
    response = _run(
        request_with_retry("GET", "https://example.test/x", max_retries=2, backoff_base=0.0)
    )
    assert response.status_code == 200
    assert len(seen) == 2


def test_retry_handles_transport_errors():
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectError("synthetic", request=request)
        return httpx.Response(200, json={"ok": True})

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = _run(
        request_with_retry("GET", "https://example.test/x", max_retries=3, backoff_base=0.0)
    )
    assert response.status_code == 200
    assert attempts["n"] == 3


def test_retry_re_raises_persistent_transport_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic", request=request)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.ConnectError):
        _run(
            request_with_retry("GET", "https://example.test/x", max_retries=2, backoff_base=0.0)
        )


# --- TTLCache LRU eviction -------------------------------------------------


def test_cache_default_max_entries_is_capped():
    cache = TTLCache(ttl_seconds=60)
    assert cache._max_entries == DEFAULT_CACHE_MAX_ENTRIES  # type: ignore[attr-defined]


def test_cache_evicts_least_recently_used():
    cache = TTLCache(ttl_seconds=60, max_entries=3)

    async def scenario():
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("c", 3)
        # Touching "a" makes "b" the LRU.
        await cache.get("a")
        await cache.set("d", 4)
        return [
            await cache.get("a"),
            await cache.get("b"),
            await cache.get("c"),
            await cache.get("d"),
        ]

    a, b, c, d = _run(scenario())
    assert a == 1
    assert b is None  # evicted
    assert c == 3
    assert d == 4


def test_cache_set_evicts_when_replacing_does_not_double_count():
    cache = TTLCache(ttl_seconds=60, max_entries=2)

    async def scenario():
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.set("a", 99)  # update, not insert
        await cache.set("c", 3)
        return [await cache.get("a"), await cache.get("b"), await cache.get("c")]

    a, b, c = _run(scenario())
    # "a" was promoted by the update and "b" is the LRU now.
    assert a == 99
    assert b is None
    assert c == 3


def test_cache_rejects_non_positive_max_entries():
    with pytest.raises(ValueError):
        TTLCache(ttl_seconds=60, max_entries=0)
