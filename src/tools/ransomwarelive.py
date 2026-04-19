"""ransomware.live v2 tools.

Surfaces metadata about recent ransomware leak-site victims, per-group
activity, per-country activity, and the active-groups directory. The v2
API is free and unauthenticated but rate-limited to ~1 request per minute
per endpoint, so every helper goes through the shared TTL cache.

Per project policy we only expose **metadata** (victim name, group,
country, sector, dates, claim URL, a short description and press links).
We deliberately drop the ``infostealer`` block and any other leaked-data
body so that the response stays safe to feed into Security Copilot.

Docs: https://www.ransomware.live/apidocs (base: https://api.ransomware.live/v2)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, get_client

RANSOMWARE_LIVE_BASE = "https://api.ransomware.live/v2"

router = APIRouter(prefix="/ransomware", tags=["ransomware"])
_cache = TTLCache(ttl_seconds=600)

_TTL_RECENT = 600
_TTL_BY_KEY = 1800
_TTL_GROUPS = 3600

MAX_RESULTS = 200


class RansomwareVictim(BaseModel):
    victim: str
    group: str | None = None
    country: str | None = None
    activity: str | None = None
    attackdate: str | None = None
    discovered: str | None = None
    claim_url: str | None = None
    domain: str | None = None
    description: str | None = None
    press: list[str] | None = None


class RansomwareGroup(BaseModel):
    name: str
    altname: str | None = None
    description: str | None = None
    first_seen: str | None = None
    victim_count: int | None = None


def _as_victim(item: dict[str, Any]) -> RansomwareVictim:
    press_raw = item.get("press")
    if isinstance(press_raw, list):
        press = [str(p) for p in press_raw if p]
    elif isinstance(press_raw, str) and press_raw:
        press = [press_raw]
    else:
        press = None

    name = item.get("victim") or item.get("name") or ""
    description = item.get("description")
    if isinstance(description, str) and len(description) > 600:
        description = description[:600].rstrip() + "…"

    return RansomwareVictim(
        victim=name,
        group=item.get("group"),
        country=item.get("country"),
        activity=item.get("activity"),
        attackdate=item.get("attackdate"),
        discovered=item.get("discovered"),
        claim_url=item.get("claim_url") or item.get("url"),
        domain=item.get("domain") or None,
        description=description,
        press=press,
    )


def _as_group(item: dict[str, Any]) -> RansomwareGroup:
    description = item.get("description")
    if isinstance(description, str) and len(description) > 400:
        description = description[:400].rstrip() + "…"
    victim_count = item.get("_victim_count")
    if not isinstance(victim_count, int):
        victim_count = None
    return RansomwareGroup(
        name=str(item.get("name", "")),
        altname=item.get("altname"),
        description=description,
        first_seen=item.get("date"),
        victim_count=victim_count,
    )


async def _get(path: str, ttl: int) -> Any:
    cached = await _cache.get(path)
    if cached is not None:
        return cached

    client = await get_client()
    response = await client.get(f"{RANSOMWARE_LIVE_BASE}{path}")
    if response.status_code == 404:
        return []
    if response.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail=(
                "ransomware.live v2 rate limit hit (1 req/min per endpoint). "
                "Retry shortly or obtain a free API PRO key at https://my.ransomware.live/."
            ),
        )
    if response.status_code >= 500:
        raise HTTPException(
            status_code=503,
            detail="ransomware.live upstream is currently unavailable.",
        )
    response.raise_for_status()
    payload = response.json()
    await _cache.set(path, payload, ttl=ttl)
    return payload


async def _recent(limit: int) -> list[RansomwareVictim]:
    data = await _get("/recentvictims", ttl=_TTL_RECENT)
    if not isinstance(data, list):
        return []
    return [_as_victim(item) for item in data[:limit]]


async def _by_group(group: str, limit: int) -> list[RansomwareVictim]:
    safe = group.strip().lower()
    if not safe or "/" in safe:
        raise HTTPException(status_code=400, detail="group must be a bare name")
    data = await _get(f"/groupvictims/{safe}", ttl=_TTL_BY_KEY)
    if not isinstance(data, list):
        return []
    return [_as_victim(item) for item in data[:limit]]


async def _by_country(country: str, limit: int) -> list[RansomwareVictim]:
    code = country.strip().upper()
    if len(code) != 2 or not code.isalpha():
        raise HTTPException(status_code=400, detail="country must be an ISO-3166-1 alpha-2 code")
    data = await _get(f"/countryvictims/{code}", ttl=_TTL_BY_KEY)
    if not isinstance(data, list):
        return []
    return [_as_victim(item) for item in data[:limit]]


async def _groups(limit: int) -> list[RansomwareGroup]:
    data = await _get("/groups", ttl=_TTL_GROUPS)
    if not isinstance(data, list):
        return []
    return [_as_group(item) for item in data[:limit]]


# --- REST -------------------------------------------------------------------


@router.get(
    "/recent",
    response_model=list[RansomwareVictim],
    summary="Recently disclosed ransomware victims (ransomware.live)",
    description=(
        "Returns the latest victims published on ransomware group leak sites, "
        "aggregated by ransomware.live. Metadata only.\n\n"
        "#ExamplePrompts\n"
        "- Show recently disclosed ransomware victims.\n"
        "- List the latest 50 ransomware leak-site victims.\n"
        "- Brief me on this week's ransomware activity."
    ),
)
async def ransomware_recent_endpoint(
    limit: int = Query(25, ge=1, le=MAX_RESULTS),
) -> list[RansomwareVictim]:
    return await _recent(limit)


@router.get(
    "/by_group",
    response_model=list[RansomwareVictim],
    summary="Victims claimed by a specific ransomware group",
    description=(
        "Returns leak-site victims attributed to a single ransomware group.\n\n"
        "#ExamplePrompts\n"
        "- List victims claimed by LockBit3.\n"
        "- Show recent victims of the BlackCat ransomware group.\n"
        "- Which organizations did Cl0p list on their leak site?"
    ),
)
async def ransomware_by_group_endpoint(
    group: str = Query(..., min_length=2, examples=["lockbit3"]),
    limit: int = Query(50, ge=1, le=MAX_RESULTS),
) -> list[RansomwareVictim]:
    return await _by_group(group, limit)


@router.get(
    "/by_country",
    response_model=list[RansomwareVictim],
    summary="Ransomware victims in a specific country (ISO-3166-1 alpha-2)",
    description=(
        "Returns leak-site victims located in the specified country (ISO 3166-1 "
        "alpha-2 code).\n\n"
        "#ExamplePrompts\n"
        "- List ransomware victims in Japan.\n"
        "- Show ransomware victims in the United States this month.\n"
        "- Any ransomware victims in DE recently?"
    ),
)
async def ransomware_by_country_endpoint(
    country: str = Query(..., min_length=2, max_length=2, examples=["JP"]),
    limit: int = Query(50, ge=1, le=MAX_RESULTS),
) -> list[RansomwareVictim]:
    return await _by_country(country, limit)


@router.get(
    "/groups",
    response_model=list[RansomwareGroup],
    summary="Directory of tracked ransomware groups",
    description=(
        "Returns a lightweight summary (name, altname, description, first seen, "
        "victim count) for each ransomware group tracked by ransomware.live.\n\n"
        "#ExamplePrompts\n"
        "- List all tracked ransomware groups.\n"
        "- Which ransomware groups are most active right now?\n"
        "- Give me a directory of known ransomware operators."
    ),
)
async def ransomware_groups_endpoint(
    limit: int = Query(100, ge=1, le=500),
) -> list[RansomwareGroup]:
    return await _groups(limit)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="ransomware_live_recent",
        description=(
            "Return recently disclosed ransomware victims (leak-site metadata) "
            "aggregated by ransomware.live. Use to brief the SOC on the latest "
            "leaks."
        ),
    )
    async def recent_mcp(limit: int = 25) -> list[dict[str, Any]]:
        return [v.model_dump() for v in await _recent(limit)]

    @mcp.tool(
        name="ransomware_live_by_group",
        description=(
            "Return victims claimed by a specific ransomware group. "
            "Use a ransomware.live group name like 'lockbit3', 'alphv', 'clop'."
        ),
    )
    async def by_group_mcp(group: str, limit: int = 50) -> list[dict[str, Any]]:
        return [v.model_dump() for v in await _by_group(group, limit)]

    @mcp.tool(
        name="ransomware_live_by_country",
        description=(
            "Return ransomware victims in a given country. "
            "country is ISO-3166-1 alpha-2, e.g. 'JP', 'US', 'DE'."
        ),
    )
    async def by_country_mcp(country: str, limit: int = 50) -> list[dict[str, Any]]:
        return [v.model_dump() for v in await _by_country(country, limit)]

    @mcp.tool(
        name="ransomware_live_groups",
        description=(
            "List ransomware groups tracked by ransomware.live with a short "
            "summary and observed victim count."
        ),
    )
    async def groups_mcp(limit: int = 100) -> list[dict[str, Any]]:
        return [g.model_dump() for g in await _groups(limit)]
