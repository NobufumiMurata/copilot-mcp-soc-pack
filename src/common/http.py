"""Shared async HTTP client with a tiny in-memory TTL cache."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

_DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
_client: httpx.AsyncClient | None = None
_client_lock = asyncio.Lock()


async def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    timeout=_DEFAULT_TIMEOUT,
                    headers={"User-Agent": "copilot-mcp-soc-pack/0.1 (+https://github.com/NobufumiMurata/copilot-mcp-soc-pack)"},
                    follow_redirects=True,
                )
    return _client


class TTLCache:
    """Minimal async-safe TTL cache keyed by string."""

    def __init__(self, ttl_seconds: int = 900) -> None:
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[float, Any]] = {}
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
            return value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        async with self._lock:
            expires_at = time.monotonic() + (ttl if ttl is not None else self._ttl)
            self._store[key] = (expires_at, value)
