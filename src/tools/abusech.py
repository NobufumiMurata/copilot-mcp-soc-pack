"""abuse.ch MalwareBazaar, ThreatFox and URLhaus tools.

All three services use the same pattern: HTTP POST to a single API endpoint
with form-urlencoded ``query=<action>`` plus query-specific parameters.

As of 2024, abuse.ch requires an ``Auth-Key`` header for every API call. A
free key can be obtained by creating an account at https://auth.abuse.ch/ .
Set the key via the ``ABUSE_CH_AUTH_KEY`` environment variable (Container
Apps can source it from a Key Vault secret).

Docs:
- https://bazaar.abuse.ch/api/
- https://threatfox.abuse.ch/api/
- https://urlhaus.abuse.ch/api/
"""

from __future__ import annotations

import os
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, get_client

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"

ABUSE_CH_AUTH_KEY_ENV = "ABUSE_CH_AUTH_KEY"

router = APIRouter(prefix="/abusech", tags=["abusech"])
_cache = TTLCache(ttl_seconds=900)


# --- Models -----------------------------------------------------------------


class MalwareBazaarSample(BaseModel):
    sha256_hash: str
    sha1_hash: str | None = None
    md5_hash: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    file_name: str | None = None
    file_size: int | None = None
    file_type: str | None = None
    signature: str | None = None
    tags: list[str] = []
    reporter: str | None = None


class ThreatFoxIOC(BaseModel):
    id: str
    ioc: str
    ioc_type: str | None = None
    threat_type: str | None = None
    malware: str | None = None
    malware_printable: str | None = None
    confidence_level: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    tags: list[str] = []
    reference: str | None = None


class UrlhausEntry(BaseModel):
    id: str | None = None
    url: str
    url_status: str | None = None
    date_added: str | None = None
    threat: str | None = None
    tags: list[str] = []
    reporter: str | None = None
    larted: str | None = None


# --- Shared helper ----------------------------------------------------------


async def _post(
    url: str, data: dict[str, Any], *, as_json: bool = False
) -> dict[str, Any]:
    """POST to an Abuse.ch endpoint and return parsed JSON.

    MalwareBazaar and URLhaus accept ``application/x-www-form-urlencoded``,
    but the ThreatFox v1 API expects a JSON body (per the official curl
    examples at https://threatfox.abuse.ch/api/). Pass ``as_json=True`` for
    ThreatFox calls.
    """
    key = os.environ.get(ABUSE_CH_AUTH_KEY_ENV)
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                "abuse.ch requires an Auth-Key for all API calls. "
                "Set ABUSE_CH_AUTH_KEY (free key from https://auth.abuse.ch/)."
            ),
        )

    cache_key = f"{url}|{'json' if as_json else 'form'}|{sorted(data.items())}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return cached

    client = await get_client()
    headers = {"Auth-Key": key}
    if as_json:
        response = await client.post(url, json=data, headers=headers)
    else:
        response = await client.post(url, data=data, headers=headers)
    if response.status_code == 401:
        raise HTTPException(
            status_code=401,
            detail="abuse.ch rejected the Auth-Key. Verify ABUSE_CH_AUTH_KEY.",
        )
    response.raise_for_status()
    payload = response.json()
    status = payload.get("query_status")
    if status not in (None, "ok", "no_results", "no_result"):
        # Surface upstream errors instead of silently returning [] downstream.
        raise HTTPException(
            status_code=502,
            detail=f"abuse.ch returned query_status={status!r} for {url}",
        )
    await _cache.set(cache_key, payload)
    return payload


def _coerce_tags(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(t) for t in raw]
    if isinstance(raw, str):
        return [raw]
    return []


# --- MalwareBazaar ----------------------------------------------------------


async def _mb_lookup(hash_value: str) -> list[MalwareBazaarSample]:
    payload = await _post(MALWAREBAZAAR_URL, {"query": "get_info", "hash": hash_value.strip()})
    if payload.get("query_status") != "ok":
        return []
    results: list[MalwareBazaarSample] = []
    for item in payload.get("data", []) or []:
        results.append(
            MalwareBazaarSample(
                sha256_hash=item.get("sha256_hash", ""),
                sha1_hash=item.get("sha1_hash"),
                md5_hash=item.get("md5_hash"),
                first_seen=item.get("first_seen"),
                last_seen=item.get("last_seen"),
                file_name=item.get("file_name"),
                file_size=item.get("file_size"),
                file_type=item.get("file_type"),
                signature=item.get("signature"),
                tags=_coerce_tags(item.get("tags")),
                reporter=item.get("reporter"),
            )
        )
    return results


async def _mb_recent(selector: str, limit: int) -> list[MalwareBazaarSample]:
    """Return the latest samples. ``selector`` is either ``"100"`` or ``"time"``."""
    payload = await _post(MALWAREBAZAAR_URL, {"query": "get_recent", "selector": selector})
    if payload.get("query_status") != "ok":
        return []
    results: list[MalwareBazaarSample] = []
    for item in (payload.get("data") or [])[:limit]:
        results.append(
            MalwareBazaarSample(
                sha256_hash=item.get("sha256_hash", ""),
                sha1_hash=item.get("sha1_hash"),
                md5_hash=item.get("md5_hash"),
                first_seen=item.get("first_seen"),
                file_name=item.get("file_name"),
                file_size=item.get("file_size"),
                file_type=item.get("file_type"),
                signature=item.get("signature"),
                tags=_coerce_tags(item.get("tags")),
                reporter=item.get("reporter"),
            )
        )
    return results


# --- ThreatFox --------------------------------------------------------------


async def _tf_recent(days: int) -> list[ThreatFoxIOC]:
    payload = await _post(
        THREATFOX_URL,
        {"query": "get_iocs", "days": max(1, min(days, 7))},
        as_json=True,
    )
    if payload.get("query_status") != "ok":
        return []
    return [
        ThreatFoxIOC(
            id=str(item.get("id", "")),
            ioc=item.get("ioc", ""),
            ioc_type=item.get("ioc_type"),
            threat_type=item.get("threat_type"),
            malware=item.get("malware"),
            malware_printable=item.get("malware_printable"),
            confidence_level=item.get("confidence_level"),
            first_seen=item.get("first_seen"),
            last_seen=item.get("last_seen"),
            tags=_coerce_tags(item.get("tags")),
            reference=item.get("reference"),
        )
        for item in (payload.get("data") or [])
    ]


async def _tf_search_ioc(ioc: str) -> list[ThreatFoxIOC]:
    payload = await _post(
        THREATFOX_URL,
        {"query": "search_ioc", "search_term": ioc.strip()},
        as_json=True,
    )
    if payload.get("query_status") != "ok":
        return []
    return [
        ThreatFoxIOC(
            id=str(item.get("id", "")),
            ioc=item.get("ioc", ""),
            ioc_type=item.get("ioc_type"),
            threat_type=item.get("threat_type"),
            malware=item.get("malware"),
            malware_printable=item.get("malware_printable"),
            confidence_level=item.get("confidence_level"),
            first_seen=item.get("first_seen"),
            last_seen=item.get("last_seen"),
            tags=_coerce_tags(item.get("tags")),
            reference=item.get("reference"),
        )
        for item in (payload.get("data") or [])
    ]


# --- URLhaus ----------------------------------------------------------------


async def _uh_lookup_url(url: str) -> UrlhausEntry | None:
    payload = await _post(URLHAUS_URL + "url/", {"url": url.strip()})
    if payload.get("query_status") != "ok":
        return None
    return UrlhausEntry(
        id=str(payload.get("id")) if payload.get("id") is not None else None,
        url=payload.get("url", url),
        url_status=payload.get("url_status"),
        date_added=payload.get("date_added"),
        threat=payload.get("threat"),
        tags=_coerce_tags(payload.get("tags")),
        reporter=payload.get("reporter"),
        larted=payload.get("larted"),
    )


async def _uh_lookup_host(host: str) -> list[UrlhausEntry]:
    payload = await _post(URLHAUS_URL + "host/", {"host": host.strip()})
    if payload.get("query_status") != "ok":
        return []
    return [
        UrlhausEntry(
            id=str(item.get("id")) if item.get("id") is not None else None,
            url=item.get("url", ""),
            url_status=item.get("url_status"),
            date_added=item.get("date_added"),
            threat=item.get("threat"),
            tags=_coerce_tags(item.get("tags")),
            reporter=item.get("reporter"),
            larted=item.get("larted"),
        )
        for item in (payload.get("urls") or [])
    ]


# --- REST endpoints ---------------------------------------------------------


@router.get(
    "/malwarebazaar/lookup",
    response_model=list[MalwareBazaarSample],
    summary="Look up a sample on MalwareBazaar by SHA256/SHA1/MD5",
    description=(
        "Look up a malware sample on abuse.ch MalwareBazaar by hash.\n\n"
        "#ExamplePrompts\n"
        "- Look up hash 094fd325049b8a9cf6d3e5ef2a6d4cc6 on MalwareBazaar.\n"
        "- Has MalwareBazaar seen the SHA256 abc123...?\n"
        "- Show me MalwareBazaar metadata for this file hash."
    ),
)
async def mb_lookup_endpoint(
    hash_value: str = Query(..., alias="hash", min_length=32, max_length=64),
) -> list[MalwareBazaarSample]:
    return await _mb_lookup(hash_value)


@router.get(
    "/malwarebazaar/recent",
    response_model=list[MalwareBazaarSample],
    summary="List the latest samples submitted to MalwareBazaar",
    description=(
        "Return the latest samples submitted to abuse.ch MalwareBazaar.\n\n"
        "#ExamplePrompts\n"
        "- Show recent malware samples from MalwareBazaar.\n"
        "- What are the latest 25 samples on MalwareBazaar?\n"
        "- Brief me on new malware seen by abuse.ch in the last hour."
    ),
)
async def mb_recent_endpoint(
    window: Literal["100", "time"] = Query(
        "100", description="'100' = latest 100 samples, 'time' = last 60 minutes."
    ),
    limit: int = Query(25, ge=1, le=100),
) -> list[MalwareBazaarSample]:
    return await _mb_recent(window, limit)


@router.get(
    "/threatfox/recent",
    response_model=list[ThreatFoxIOC],
    summary="Fetch recent IOCs from ThreatFox",
    description=(
        "Return recent indicators of compromise from abuse.ch ThreatFox.\n\n"
        "#ExamplePrompts\n"
        "- Show recent ThreatFox IOCs from the last 3 days.\n"
        "- What new IOCs has ThreatFox published this week?\n"
        "- Pull the latest abuse.ch ThreatFox indicators."
    ),
)
async def tf_recent_endpoint(
    days: int = Query(3, ge=1, le=7, description="Look-back window (max 7 days).")
) -> list[ThreatFoxIOC]:
    return await _tf_recent(days)


@router.get(
    "/threatfox/search",
    response_model=list[ThreatFoxIOC],
    summary="Search ThreatFox for an IOC",
    description=(
        "Search ThreatFox for an IP address, domain, URL or file hash.\n\n"
        "#ExamplePrompts\n"
        "- Search ThreatFox for the IOC 1.2.3.4.\n"
        "- Does ThreatFox have any indicators for evil.example.com?\n"
        "- Look up this hash in abuse.ch ThreatFox."
    ),
)
async def tf_search_endpoint(
    ioc: str = Query(..., min_length=3, examples=["1.2.3.4"]),
) -> list[ThreatFoxIOC]:
    return await _tf_search_ioc(ioc)


@router.get(
    "/urlhaus/url",
    response_model=UrlhausEntry | None,
    summary="Look up a URL on URLhaus",
    description=(
        "Look up a single URL on abuse.ch URLhaus.\n\n"
        "#ExamplePrompts\n"
        "- Is http://example.com/malware.exe known to URLhaus?\n"
        "- Check this URL against abuse.ch URLhaus.\n"
        "- What does URLhaus say about this download link?"
    ),
)
async def uh_url_endpoint(
    url: str = Query(..., examples=["http://example.com/malware.exe"])
) -> UrlhausEntry | None:
    return await _uh_lookup_url(url)


@router.get(
    "/urlhaus/host",
    response_model=list[UrlhausEntry],
    summary="Look up all URLhaus entries associated with a host (IP or domain)",
    description=(
        "Return every URLhaus entry associated with a host (IP or domain).\n\n"
        "#ExamplePrompts\n"
        "- List URLhaus entries for the host evil.example.com.\n"
        "- What malware URLs has abuse.ch seen on 1.2.3.4?\n"
        "- Show me every URLhaus record for this domain."
    ),
)
async def uh_host_endpoint(
    host: str = Query(..., min_length=3, examples=["example.com"])
) -> list[UrlhausEntry]:
    return await _uh_lookup_host(host)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="malwarebazaar_lookup",
        description=(
            "Look up a malware sample on abuse.ch MalwareBazaar by MD5, SHA1, or "
            "SHA256 hash. Returns reporter, signature, first/last seen, tags."
        ),
    )
    async def mb_lookup_mcp(hash_value: str) -> list[dict[str, Any]]:
        if not 32 <= len(hash_value.strip()) <= 64:
            raise HTTPException(status_code=400, detail="hash must be MD5/SHA1/SHA256")
        return [s.model_dump() for s in await _mb_lookup(hash_value)]

    @mcp.tool(
        name="malwarebazaar_recent",
        description=(
            "List recent samples submitted to MalwareBazaar "
            "(last 60 minutes or last 100 samples)."
        ),
    )
    async def mb_recent_mcp(window: str = "100", limit: int = 25) -> list[dict[str, Any]]:
        if window not in {"100", "time"}:
            window = "100"
        return [s.model_dump() for s in await _mb_recent(window, limit)]

    @mcp.tool(
        name="threatfox_recent",
        description="Fetch recent IOCs from abuse.ch ThreatFox (up to 7 days).",
    )
    async def tf_recent_mcp(days: int = 3) -> list[dict[str, Any]]:
        return [i.model_dump() for i in await _tf_recent(days)]

    @mcp.tool(
        name="threatfox_search",
        description="Search abuse.ch ThreatFox for an IOC (IP, domain, URL, or hash).",
    )
    async def tf_search_mcp(ioc: str) -> list[dict[str, Any]]:
        return [i.model_dump() for i in await _tf_search_ioc(ioc)]

    @mcp.tool(
        name="urlhaus_lookup_url",
        description="Look up a URL on abuse.ch URLhaus. Returns status, threat, tags.",
    )
    async def uh_url_mcp(url: str) -> dict[str, Any] | None:
        entry = await _uh_lookup_url(url)
        return entry.model_dump() if entry else None

    @mcp.tool(
        name="urlhaus_lookup_host",
        description="Return every URLhaus entry associated with a host (IP or domain).",
    )
    async def uh_host_mcp(host: str) -> list[dict[str, Any]]:
        return [e.model_dump() for e in await _uh_lookup_host(host)]
