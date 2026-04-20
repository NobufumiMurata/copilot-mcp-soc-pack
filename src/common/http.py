"""Shared async HTTP client with a tiny in-memory TTL cache.

Two pieces of plumbing every tool relies on:

- ``get_client()`` — returns a process-wide ``httpx.AsyncClient`` that
  uses an ``AsyncHTTPTransport`` with built-in connection retries. We
  layer a thin async retry helper (``request_with_retry``) on top so we
  can also retry transient HTTP responses (5xx and 429) with exponential
  backoff and jitter, which the bare ``transport.retries`` setting does
  not handle.

- ``TTLCache`` — async-safe TTL cache with an LRU-style size cap so the
  scale-to-zero container can run for hours without leaking memory if a
  caller hammers it with unique cache keys.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import OrderedDict
from typing import Any

import httpx

from src import __version__

_DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
_USER_AGENT = (
    f"copilot-mcp-soc-pack/{__version__} "
    "(+https://github.com/NobufumiMurata/copilot-mcp-soc-pack)"
)

# Connection-level retries for low-level network errors (DNS, reset, etc.).
# Application-level retries (5xx, 429) are handled by ``request_with_retry``.
_TRANSPORT_RETRIES = 2

_client: httpx.AsyncClient | None = None
_client_lock = asyncio.Lock()

_log = logging.getLogger(__name__)


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    transport=httpx.AsyncHTTPTransport(retries=_TRANSPORT_RETRIES),
                    timeout=_DEFAULT_TIMEOUT,
                    headers={"User-Agent": _USER_AGENT},
                    follow_redirects=True,
                )
    return _client


# Status codes worth retrying. 408 (timeout), 425 (too early), 429 (rate
# limit), and the standard 5xx range. We deliberately do NOT retry other
# 4xx codes because they almost always indicate a permanent client-side
# problem (bad input, missing key, etc.).
_RETRY_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})

DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_BASE = 0.5  # seconds
DEFAULT_BACKOFF_CAP = 5.0  # seconds


async def request_with_retry(
    method: str,
    url: str,
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
    backoff_cap: float = DEFAULT_BACKOFF_CAP,
    **kwargs: Any,
) -> httpx.Response:
    """Issue an HTTP request and retry transient failures with backoff.

    Retries on:
    - ``httpx.TransportError`` / ``httpx.TimeoutException``
      (connection refused, read timeout, DNS failure...)
    - HTTP responses with status codes in ``_RETRY_STATUS_CODES``.

    The ``Retry-After`` response header (seconds-only form) is honoured
    when present, otherwise we use exponential backoff with full jitter:
    ``random_uniform(0, min(cap, base * 2**attempt))``.
    """
    client = await get_client()
    last_response: httpx.Response | None = None
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            response = await client.request(method, url, **kwargs)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            last_exc = exc
            if attempt >= max_retries:
                _log.warning("Exhausted retries for %s %s: %s", method, url, exc)
                raise
            delay = _compute_backoff(attempt, backoff_base, backoff_cap)
            _log.info(
                "Retrying %s %s after %.2fs (transport error: %s)", method, url, delay, exc
            )
            await asyncio.sleep(delay)
            continue

        if response.status_code not in _RETRY_STATUS_CODES or attempt >= max_retries:
            return response

        last_response = response
        delay = _delay_from_retry_after(response) or _compute_backoff(
            attempt, backoff_base, backoff_cap
        )
        _log.info(
            "Retrying %s %s after %.2fs (status=%s)",
            method,
            url,
            delay,
            response.status_code,
        )
        await asyncio.sleep(delay)

    # Defensive fallthrough; the loop above always returns or raises.
    if last_response is not None:  # pragma: no cover
        return last_response
    if last_exc is not None:  # pragma: no cover
        raise last_exc
    raise RuntimeError("request_with_retry: unreachable")  # pragma: no cover


def _compute_backoff(attempt: int, base: float, cap: float) -> float:
    """Full-jitter exponential backoff (AWS Architecture Blog formula)."""
    high = min(cap, base * (2**attempt))
    return random.uniform(0.0, max(high, 0.001))


def _delay_from_retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        return None
    # Cap the upstream-provided delay so a misconfigured server cannot stall
    # the request for minutes inside a Container Apps scale-to-zero replica.
    return min(seconds, 30.0)


# Default cap. Tuned for the current scale-to-zero usage:
# 10 tools * a few hundred unique cache keys each is well under this budget.
DEFAULT_CACHE_MAX_ENTRIES = 1024


class TTLCache:
    """Async-safe TTL cache with LRU eviction.

    Keys are strings; values are arbitrary. Each ``get`` / ``set``
    promotes the key to the most-recently-used position. When the cache
    grows past ``max_entries`` we evict from the least-recently-used end
    until we are back at the cap. Expired entries are also dropped on
    read so the LRU ordering is honest.
    """

    def __init__(
        self,
        ttl_seconds: int = 900,
        max_entries: int = DEFAULT_CACHE_MAX_ENTRIES,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._store: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            expires_at, value = entry
            if expires_at < time.monotonic():
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        async with self._lock:
            expires_at = time.monotonic() + (ttl if ttl is not None else self._ttl)
            self._store[key] = (expires_at, value)
            self._store.move_to_end(key)
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def __len__(self) -> int:  # pragma: no cover - thin convenience for tests
        return len(self._store)
