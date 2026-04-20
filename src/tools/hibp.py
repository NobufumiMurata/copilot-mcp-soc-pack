"""Have I Been Pwned (HIBP) — public breach lookups.

Docs: https://haveibeenpwned.com/API/v3

The endpoints we expose require **no API key**:
- ``GET /breaches?domain={domain}`` — every public breach impacting a domain
- ``GET /breach/{name}`` — full metadata for a single breach by name

HIBP enforces a courteous rate limit and requires a descriptive User-Agent;
both are honoured via ``src/common/http.py:get_client()``.

The paid breach lookups (``breachedaccount``, ``breacheddomain``) are
intentionally not implemented — they require a per-key subscription that
goes against this project's "free APIs only" policy.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

HIBP_BASE = "https://haveibeenpwned.com/api/v3"

router = APIRouter(prefix="/hibp", tags=["hibp"])
_cache = TTLCache(ttl_seconds=3600)


class HIBPBreach(BaseModel):
    Name: str
    Title: str | None = None
    Domain: str | None = None
    BreachDate: str | None = None
    AddedDate: str | None = None
    ModifiedDate: str | None = None
    PwnCount: int | None = None
    Description: str | None = None
    DataClasses: list[str] = []
    IsVerified: bool | None = None
    IsFabricated: bool | None = None
    IsSensitive: bool | None = None
    IsRetired: bool | None = None
    IsSpamList: bool | None = None
    IsMalware: bool | None = None
    LogoPath: str | None = None


def _to_breach(raw: dict[str, Any]) -> HIBPBreach:
    return HIBPBreach(
        Name=str(raw.get("Name", "")),
        Title=raw.get("Title"),
        Domain=raw.get("Domain"),
        BreachDate=raw.get("BreachDate"),
        AddedDate=raw.get("AddedDate"),
        ModifiedDate=raw.get("ModifiedDate"),
        PwnCount=raw.get("PwnCount"),
        Description=raw.get("Description"),
        DataClasses=list(raw.get("DataClasses") or []),
        IsVerified=raw.get("IsVerified"),
        IsFabricated=raw.get("IsFabricated"),
        IsSensitive=raw.get("IsSensitive"),
        IsRetired=raw.get("IsRetired"),
        IsSpamList=raw.get("IsSpamList"),
        IsMalware=raw.get("IsMalware"),
        LogoPath=raw.get("LogoPath"),
    )


async def _breaches_for_domain(domain: str) -> list[HIBPBreach]:
    target = domain.strip().lower()
    if not target:
        raise HTTPException(status_code=400, detail="domain must not be empty.")

    cache_key = f"domain|{target}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return [HIBPBreach(**b) for b in cached]

    # 5xx and 429 are transient; retry via the shared backoff helper. After
    # the retry budget is exhausted the final response (including 429 / 503)
    # is returned and translated below.
    response = await request_with_retry(
        "GET", f"{HIBP_BASE}/breaches", params={"domain": target}
    )
    if response.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail="HIBP rate limit reached (advisory ~1.5 req/sec).",
        )
    if response.status_code == 503:
        raise HTTPException(status_code=503, detail="HIBP is currently unavailable.")
    response.raise_for_status()

    payload = response.json() or []
    if not isinstance(payload, list):
        return []
    breaches = [_to_breach(b) for b in payload if isinstance(b, dict)]
    await _cache.set(cache_key, [b.model_dump() for b in breaches])
    return breaches


async def _breach_by_name(name: str) -> HIBPBreach | None:
    target = name.strip()
    if not target:
        raise HTTPException(status_code=400, detail="name must not be empty.")

    cache_key = f"name|{target.lower()}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return HIBPBreach(**cached) if cached else None

    # 5xx and 429 are transient; retry via the shared backoff helper.
    response = await request_with_retry("GET", f"{HIBP_BASE}/breach/{target}")
    if response.status_code == 404:
        await _cache.set(cache_key, None)
        return None
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="HIBP rate limit reached.")
    response.raise_for_status()
    breach = _to_breach(response.json() or {})
    await _cache.set(cache_key, breach.model_dump())
    return breach


# --- REST -------------------------------------------------------------------


@router.get(
    "/breaches_by_domain",
    response_model=list[HIBPBreach],
    summary="List all public breaches that impacted a given domain (HIBP)",
    description=(
        "Returns every public breach in Have I Been Pwned that exposed accounts "
        "on the given domain. No API key required.\n\n"
        "#ExamplePrompts\n"
        "- Has adobe.com ever been part of a public data breach?\n"
        "- List Have I Been Pwned breaches for linkedin.com.\n"
        "- Which HIBP breaches impacted yahoo.com and what data was leaked?"
    ),
)
async def hibp_breaches_by_domain_endpoint(
    domain: str = Query(..., min_length=3, examples=["adobe.com"]),
) -> list[HIBPBreach]:
    return await _breaches_for_domain(domain)


@router.get(
    "/breach",
    response_model=HIBPBreach | None,
    summary="Get full metadata for a single named breach (HIBP)",
    description=(
        "Returns Have I Been Pwned metadata for a specific breach by its short "
        "name (e.g. 'Adobe', 'LinkedIn'). Returns null when the name is unknown.\n\n"
        "#ExamplePrompts\n"
        "- Tell me about the LinkedIn breach on Have I Been Pwned.\n"
        "- What data classes were exposed in the Adobe HIBP breach?\n"
        "- When did the Dropbox HIBP breach happen?"
    ),
)
async def hibp_breach_endpoint(
    name: str = Query(..., min_length=2, examples=["Adobe"]),
) -> HIBPBreach | None:
    return await _breach_by_name(name)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="hibp_breaches_by_domain",
        description=(
            "List every public Have I Been Pwned breach that impacted a domain. "
            "No API key required."
        ),
    )
    async def hibp_breaches_by_domain_mcp(domain: str) -> list[dict[str, Any]]:
        return [b.model_dump() for b in await _breaches_for_domain(domain)]

    @mcp.tool(
        name="hibp_breach",
        description=(
            "Get full metadata for a named Have I Been Pwned breach "
            "(e.g. 'Adobe', 'LinkedIn'). Returns null when unknown."
        ),
    )
    async def hibp_breach_mcp(name: str) -> dict[str, Any] | None:
        b = await _breach_by_name(name)
        return b.model_dump() if b else None
