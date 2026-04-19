"""AlienVault OTX (Open Threat Exchange) indicator lookups.

Docs: https://otx.alienvault.com/assets/static/external_api.html

A free OTX account provides an ``X-OTX-API-KEY`` (Settings -> API Integration).
Set the ``OTX_API_KEY`` environment variable.

We surface the lightweight "general" section of each indicator endpoint
(reputation, pulse count, top pulses, references) rather than the full
multi-megabyte response.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, get_client

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
OTX_API_KEY_ENV = "OTX_API_KEY"
MAX_PULSES = 10

router = APIRouter(prefix="/otx", tags=["otx"])
_cache = TTLCache(ttl_seconds=900)


class OTXPulse(BaseModel):
    id: str
    name: str | None = None
    description: str | None = None
    tags: list[str] = []
    adversary: str | None = None
    malware_families: list[str] = []
    attack_ids: list[str] = []
    created: str | None = None
    modified: str | None = None
    author_name: str | None = None


class OTXIndicator(BaseModel):
    indicator: str
    type: str
    type_title: str | None = None
    reputation: int | None = None
    pulse_count: int = 0
    pulses: list[OTXPulse] = []
    false_positive: bool = False
    references: list[str] = []
    sections: list[str] = []


def _require_key() -> str:
    key = os.environ.get(OTX_API_KEY_ENV)
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                "AlienVault OTX requires a free API key. Set OTX_API_KEY "
                "(register at https://otx.alienvault.com/ and grab the key "
                "from Settings -> API Integration)."
            ),
        )
    return key


def _trim_pulse(raw: dict[str, Any]) -> OTXPulse:
    author = raw.get("author") if isinstance(raw.get("author"), dict) else {}
    return OTXPulse(
        id=str(raw.get("id", "")),
        name=raw.get("name"),
        description=(raw.get("description") or None),
        tags=list(raw.get("tags") or []),
        adversary=raw.get("adversary") or None,
        malware_families=[
            (m.get("display_name") or m.get("name") or "")
            for m in (raw.get("malware_families") or [])
            if isinstance(m, dict)
        ],
        attack_ids=[
            (a.get("id") or a.get("display_name") or "")
            for a in (raw.get("attack_ids") or [])
            if isinstance(a, dict)
        ],
        created=raw.get("created"),
        modified=raw.get("modified"),
        author_name=author.get("username") if author else None,
    )


def _to_indicator(target: str, indicator_type: str, payload: dict[str, Any]) -> OTXIndicator:
    pulse_info = payload.get("pulse_info") or {}
    pulses_raw = pulse_info.get("pulses") or []
    references = pulse_info.get("references") or []
    return OTXIndicator(
        indicator=payload.get("indicator", target),
        type=payload.get("type", indicator_type),
        type_title=payload.get("type_title"),
        reputation=payload.get("reputation"),
        pulse_count=int(pulse_info.get("count") or 0),
        pulses=[_trim_pulse(p) for p in pulses_raw[:MAX_PULSES] if isinstance(p, dict)],
        false_positive=bool(payload.get("false_positive")),
        references=[str(r) for r in references if r],
        sections=list(payload.get("sections") or []),
    )


async def _otx_get(indicator_type: str, target: str) -> OTXIndicator:
    key = _require_key()
    cache_key = f"{indicator_type}|{target.lower()}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return OTXIndicator(**cached)

    url = f"{OTX_BASE}/{indicator_type}/{target}/general"
    client = await get_client()
    response = await client.get(url, headers={"X-OTX-API-KEY": key, "Accept": "application/json"})
    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="OTX rejected the API key. Verify OTX_API_KEY.")
    if response.status_code == 404:
        # OTX returns 404 for unknown indicators; surface an empty result.
        empty = OTXIndicator(indicator=target, type=indicator_type)
        await _cache.set(cache_key, empty.model_dump())
        return empty
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="OTX rate limit reached.")
    response.raise_for_status()

    result = _to_indicator(target, indicator_type, response.json() or {})
    await _cache.set(cache_key, result.model_dump())
    return result


# Hash type detection -------------------------------------------------------

_HASH_TYPES: dict[int, str] = {32: "file", 40: "file", 64: "file"}


def _hash_section(value: str) -> str:
    if len(value) not in _HASH_TYPES:
        raise HTTPException(
            status_code=400,
            detail="hash must be MD5 (32), SHA1 (40), or SHA256 (64) hex characters.",
        )
    return "file"


# --- REST -------------------------------------------------------------------


@router.get(
    "/ipv4",
    response_model=OTXIndicator,
    summary="Look up an IPv4 indicator on AlienVault OTX",
    description=(
        "Returns OTX reputation, pulse count, and the top pulses (community "
        "threat-intel reports) referencing this IP.\n\n"
        "#ExamplePrompts\n"
        "- What does AlienVault OTX say about 1.2.3.4?\n"
        "- Is 45.155.205.233 mentioned in any OTX pulses?\n"
        "- Show OTX threat-intel pulses tagging this IP."
    ),
)
async def otx_ipv4_endpoint(
    ip: str = Query(..., examples=["8.8.8.8"]),
) -> OTXIndicator:
    return await _otx_get("IPv4", ip.strip())


@router.get(
    "/ipv6",
    response_model=OTXIndicator,
    summary="Look up an IPv6 indicator on AlienVault OTX",
    description=(
        "Returns OTX reputation and pulses for an IPv6 address.\n\n"
        "#ExamplePrompts\n"
        "- Look up the IPv6 address 2001:db8::1 on OTX.\n"
        "- Any OTX pulses for this IPv6 indicator?"
    ),
)
async def otx_ipv6_endpoint(
    ip: str = Query(..., examples=["2001:4860:4860::8888"]),
) -> OTXIndicator:
    return await _otx_get("IPv6", ip.strip())


@router.get(
    "/domain",
    response_model=OTXIndicator,
    summary="Look up a domain (or hostname) indicator on AlienVault OTX",
    description=(
        "Returns OTX pulses, reputation, and references for a domain or hostname.\n\n"
        "#ExamplePrompts\n"
        "- What does AlienVault OTX have on evil.example.com?\n"
        "- Show OTX pulses tagging contoso.com.\n"
        "- Has malicious-domain.tld been seen by OTX?"
    ),
)
async def otx_domain_endpoint(
    domain: str = Query(..., min_length=3, examples=["example.com"]),
    kind: Literal["domain", "hostname"] = Query(
        "domain", description="OTX distinguishes registered domains from hostnames."
    ),
) -> OTXIndicator:
    indicator_type = "domain" if kind == "domain" else "hostname"
    return await _otx_get(indicator_type, domain.strip().lower())


@router.get(
    "/file",
    response_model=OTXIndicator,
    summary="Look up a file hash (MD5/SHA1/SHA256) on AlienVault OTX",
    description=(
        "Returns OTX pulses and references for a file hash.\n\n"
        "#ExamplePrompts\n"
        "- Has AlienVault OTX seen the SHA256 abc123...?\n"
        "- Look up this MD5 in OTX.\n"
        "- Show OTX pulses for file hash 094fd325049b8a9cf6d3e5ef2a6d4cc6."
    ),
)
async def otx_file_endpoint(
    hash_value: str = Query(..., alias="hash", min_length=32, max_length=64),
) -> OTXIndicator:
    target = hash_value.strip()
    _hash_section(target)
    return await _otx_get("file", target)


@router.get(
    "/url",
    response_model=OTXIndicator,
    summary="Look up a URL indicator on AlienVault OTX",
    description=(
        "Returns OTX pulses and references for a URL.\n\n"
        "#ExamplePrompts\n"
        "- Has OTX seen this URL: http://example.com/malware.exe ?\n"
        "- Show OTX threat-intel pulses for this download link."
    ),
)
async def otx_url_endpoint(
    url: str = Query(..., min_length=4, examples=["http://example.com/malware.exe"]),
) -> OTXIndicator:
    return await _otx_get("url", url.strip())


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="otx_lookup_ipv4",
        description=(
            "Look up an IPv4 address on AlienVault OTX. Returns reputation, "
            "pulse count and top pulses (community threat-intel reports)."
        ),
    )
    async def otx_ipv4_mcp(ip: str) -> dict[str, Any]:
        return (await _otx_get("IPv4", ip.strip())).model_dump()

    @mcp.tool(
        name="otx_lookup_ipv6",
        description="Look up an IPv6 address on AlienVault OTX.",
    )
    async def otx_ipv6_mcp(ip: str) -> dict[str, Any]:
        return (await _otx_get("IPv6", ip.strip())).model_dump()

    @mcp.tool(
        name="otx_lookup_domain",
        description=(
            "Look up a domain or hostname on AlienVault OTX. "
            "Set kind='hostname' for non-registered hosts."
        ),
    )
    async def otx_domain_mcp(domain: str, kind: str = "domain") -> dict[str, Any]:
        indicator_type = "domain" if kind != "hostname" else "hostname"
        return (await _otx_get(indicator_type, domain.strip().lower())).model_dump()

    @mcp.tool(
        name="otx_lookup_file",
        description="Look up a file hash (MD5/SHA1/SHA256) on AlienVault OTX.",
    )
    async def otx_file_mcp(hash_value: str) -> dict[str, Any]:
        target = hash_value.strip()
        _hash_section(target)
        return (await _otx_get("file", target)).model_dump()

    @mcp.tool(
        name="otx_lookup_url",
        description="Look up a URL on AlienVault OTX.",
    )
    async def otx_url_mcp(url: str) -> dict[str, Any]:
        return (await _otx_get("url", url.strip())).model_dump()
