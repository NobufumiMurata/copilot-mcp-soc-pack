"""crt.sh certificate transparency lookup.

Fetches every CT log entry matching ``%.<domain>`` and returns the unique
sorted set of subdomains. Unauthenticated, but crt.sh throttles noisy
clients — we send an explicit User-Agent and cap the returned list.

Docs: https://crt.sh (append ``&output=json``)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, get_client

CRTSH_URL = "https://crt.sh/"
CRTSH_USER_AGENT = "copilot-mcp-soc-pack/0.3 (+https://github.com/NobufumiMurata/copilot-mcp-soc-pack)"

MAX_SUBDOMAINS = 500

router = APIRouter(prefix="/crtsh", tags=["crtsh"])
_cache = TTLCache(ttl_seconds=7200)


class CrtshSubdomainsResult(BaseModel):
    domain: str
    count: int
    truncated: bool
    subdomains: list[str]
    source_entries: int
    message: str | None = None


def _normalize(name: str) -> str | None:
    name = name.strip().lower().rstrip(".")
    if not name or name.startswith("*."):
        # Skip wildcard entries; they don't represent real hosts.
        return None
    # Ignore email addresses that occasionally appear in CT entries.
    if "@" in name:
        return None
    return name


async def _subdomains(domain: str) -> CrtshSubdomainsResult:
    target = domain.strip().lower().lstrip(".")
    if not target or " " in target or "/" in target:
        raise HTTPException(status_code=400, detail="domain must be a bare host name")

    cached = await _cache.get(target)
    if cached is not None:
        return CrtshSubdomainsResult(**cached)

    client = await get_client()
    response = await client.get(
        CRTSH_URL,
        params={"q": f"%.{target}", "output": "json"},
        headers={"User-Agent": CRTSH_USER_AGENT, "Accept": "application/json"},
    )
    if response.status_code == 404:
        # crt.sh returns 404 when no certs match — normalise to an empty result.
        empty = CrtshSubdomainsResult(
            domain=target, count=0, truncated=False, subdomains=[], source_entries=0
        )
        await _cache.set(target, empty.model_dump())
        return empty
    if response.status_code >= 500:
        raise HTTPException(
            status_code=503,
            detail="crt.sh upstream is currently unavailable. Retry later.",
        )
    response.raise_for_status()

    try:
        entries = response.json()
    except ValueError as exc:  # crt.sh occasionally returns partial HTML on load
        raise HTTPException(
            status_code=503,
            detail="crt.sh returned a non-JSON response (likely overloaded).",
        ) from exc

    unique: set[str] = set()
    for entry in entries or []:
        raw = entry.get("name_value")
        if not raw:
            continue
        for line in raw.splitlines():
            normalized = _normalize(line)
            if normalized and (normalized == target or normalized.endswith("." + target)):
                unique.add(normalized)

    sorted_subs = sorted(unique)
    truncated = len(sorted_subs) > MAX_SUBDOMAINS
    if truncated:
        sorted_subs = sorted_subs[:MAX_SUBDOMAINS]

    result = CrtshSubdomainsResult(
        domain=target,
        count=len(sorted_subs),
        truncated=truncated,
        subdomains=sorted_subs,
        source_entries=len(entries) if entries else 0,
        message=(
            f"Result capped at {MAX_SUBDOMAINS} subdomains; narrow the query for more."
            if truncated
            else None
        ),
    )
    await _cache.set(target, result.model_dump())
    return result


# --- REST -------------------------------------------------------------------


@router.get(
    "/subdomains",
    response_model=CrtshSubdomainsResult,
    summary="Enumerate subdomains via crt.sh certificate transparency",
    description=(
        "Queries crt.sh for all certificates issued for ``%.<domain>`` and returns "
        "the unique, sorted subdomain set. Capped at 500 entries.\n\n"
        "#ExamplePrompts\n"
        "- Enumerate subdomains of example.com from CT logs.\n"
        "- What subdomains has crt.sh seen for contoso.com?\n"
        "- List certificate transparency subdomains for github.io."
    ),
)
async def crtsh_subdomains_endpoint(
    domain: str = Query(..., min_length=3, examples=["example.com"]),
) -> CrtshSubdomainsResult:
    return await _subdomains(domain)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="crtsh_subdomains",
        description=(
            "Enumerate subdomains of a domain via crt.sh Certificate Transparency. "
            "Returns a unique sorted list (capped at 500)."
        ),
    )
    async def crtsh_subdomains_mcp(domain: str) -> dict[str, Any]:
        return (await _subdomains(domain)).model_dump()
