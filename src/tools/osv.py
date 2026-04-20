"""OSV.dev — open source vulnerability database tools.

Docs: https://google.github.io/osv.dev/api/

Three free, key-less endpoints:

- ``POST /v1/query``  — query vulnerabilities by package + version, or by commit hash
- ``GET  /v1/vulns/{id}`` — fetch the full record for an OSV / GHSA / CVE id

OSV's vulnerability schema (https://ossf.github.io/osv-schema/) is deeply
nested and varies by ecosystem, so we deliberately surface the response
``vulns`` list as ``list[dict[str, Any]]`` rather than re-modelling it.
This keeps the tool useful when OSV adds new fields without forcing a
release here.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

router = APIRouter(prefix="/osv", tags=["osv"])
# Package queries change a few times a day at most; vuln details rarely
# change once published. Use separate TTLs.
_query_cache = TTLCache(ttl_seconds=1800)  # 30 min
_vuln_cache = TTLCache(ttl_seconds=7200)  # 2 hours


class OsvQueryResult(BaseModel):
    vulns: list[dict[str, Any]] = []
    next_page_token: str | None = None


async def _post_query(body: dict[str, Any]) -> OsvQueryResult:
    cache_key = repr(sorted(body.items()))
    cached = await _query_cache.get(cache_key)
    if cached is not None:
        return OsvQueryResult(**cached)

    response = await request_with_retry("POST", OSV_QUERY_URL, json=body)
    if response.status_code == 400:
        # OSV returns 400 with a JSON error body for malformed requests.
        try:
            detail = response.json().get("message") or response.text
        except ValueError:
            detail = response.text
        raise HTTPException(status_code=400, detail=f"OSV rejected the query: {detail}")
    if response.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail="OSV.dev rate limit reached. Retry shortly.",
        )
    if response.status_code >= 500:
        raise HTTPException(status_code=503, detail="OSV.dev upstream is currently unavailable.")
    response.raise_for_status()

    payload = response.json() or {}
    result = OsvQueryResult(
        vulns=list(payload.get("vulns") or []),
        next_page_token=payload.get("next_page_token"),
    )
    await _query_cache.set(cache_key, result.model_dump())
    return result


async def _query_package(
    name: str, ecosystem: str, version: str | None = None
) -> OsvQueryResult:
    safe_name = name.strip()
    safe_ecosystem = ecosystem.strip()
    if not safe_name or not safe_ecosystem:
        raise HTTPException(status_code=400, detail="name and ecosystem must not be empty.")
    body: dict[str, Any] = {"package": {"name": safe_name, "ecosystem": safe_ecosystem}}
    if version:
        body["version"] = version.strip()
    return await _post_query(body)


async def _query_commit(commit: str) -> OsvQueryResult:
    target = commit.strip().lower()
    if not target:
        raise HTTPException(status_code=400, detail="commit must not be empty.")
    return await _post_query({"commit": target})


async def _get_vuln(vuln_id: str) -> dict[str, Any]:
    target = vuln_id.strip()
    if not target or "/" in target:
        raise HTTPException(status_code=400, detail="vuln_id must be a bare identifier.")

    cached = await _vuln_cache.get(target)
    if cached is not None:
        return cached

    response = await request_with_retry("GET", f"{OSV_VULN_URL}/{target}")
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail=f"OSV.dev has no vulnerability {target!r}.")
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="OSV.dev rate limit reached. Retry shortly.")
    if response.status_code >= 500:
        raise HTTPException(status_code=503, detail="OSV.dev upstream is currently unavailable.")
    response.raise_for_status()

    payload = response.json() or {}
    await _vuln_cache.set(target, payload)
    return payload


# --- REST -------------------------------------------------------------------


@router.get(
    "/query_package",
    response_model=OsvQueryResult,
    summary="Query OSV.dev by package + version",
    description=(
        "Returns vulnerabilities affecting a specific package version across any "
        "ecosystem indexed by OSV (PyPI, npm, Go, Maven, crates.io, RubyGems, "
        "NuGet, Packagist, Hex, Pub, OSS-Fuzz, Linux distros, etc.).\n\n"
        "#ExamplePrompts\n"
        "- Are there any known vulnerabilities in jinja2 3.1.4 on PyPI?\n"
        "- Find OSV advisories for npm package lodash 4.17.20.\n"
        "- List vulnerabilities affecting Go module github.com/gin-gonic/gin v1.7.0."
    ),
)
async def osv_query_package_endpoint(
    name: str = Query(..., examples=["jinja2"]),
    ecosystem: str = Query(..., examples=["PyPI"]),
    version: str | None = Query(None, examples=["3.1.4"]),
) -> OsvQueryResult:
    return await _query_package(name, ecosystem, version)


@router.get(
    "/query_commit",
    response_model=OsvQueryResult,
    summary="Query OSV.dev by commit hash",
    description=(
        "Returns vulnerabilities introduced or fixed by a specific git commit hash.\n\n"
        "#ExamplePrompts\n"
        "- Did commit 6879efc2c1596d11a6a6ad296f80063b558d5e0f introduce any "
        "OSV-tracked vulnerabilities?\n"
        "- Look up OSV advisories for git commit deadbeef…."
    ),
)
async def osv_query_commit_endpoint(
    commit: str = Query(..., examples=["6879efc2c1596d11a6a6ad296f80063b558d5e0f"]),
) -> OsvQueryResult:
    return await _query_commit(commit)


@router.get(
    "/vuln/{vuln_id}",
    response_model=dict[str, Any],
    summary="Fetch a single OSV / GHSA / CVE record by id",
    description=(
        "Returns the full OSV record for a vulnerability identifier. Accepts native "
        "OSV ids (``OSV-2022-XXX``), GitHub Security Advisories (``GHSA-XXX-XXX-XXX``), "
        "CVE ids, and any other id ingested by OSV.\n\n"
        "#ExamplePrompts\n"
        "- Show me the full OSV record for GHSA-h5c8-rqwp-cp95.\n"
        "- What does OSV.dev say about CVE-2024-3400?\n"
        "- Pull the OSV advisory for OSV-2022-1004."
    ),
)
async def osv_get_vuln_endpoint(vuln_id: str) -> dict[str, Any]:
    return await _get_vuln(vuln_id)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="osv_query_package",
        description=(
            "Query OSV.dev for vulnerabilities in a specific package version. Supports "
            "PyPI, npm, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Hex, Pub, "
            "OSS-Fuzz, and Linux distro ecosystems. Returns the OSV vulns list verbatim."
        ),
    )
    async def osv_query_package_mcp(
        name: str, ecosystem: str, version: str | None = None
    ) -> dict[str, Any]:
        return (await _query_package(name, ecosystem, version)).model_dump()

    @mcp.tool(
        name="osv_query_commit",
        description=(
            "Query OSV.dev for vulnerabilities introduced or fixed by a specific git "
            "commit hash. Useful for reachability / fix-validation workflows."
        ),
    )
    async def osv_query_commit_mcp(commit: str) -> dict[str, Any]:
        return (await _query_commit(commit)).model_dump()

    @mcp.tool(
        name="osv_get_vuln",
        description=(
            "Fetch the full OSV record for a vulnerability identifier (OSV-, GHSA-, "
            "CVE-, etc.). Returns the OSV-schema JSON unchanged."
        ),
    )
    async def osv_get_vuln_mcp(vuln_id: str) -> dict[str, Any]:
        return await _get_vuln(vuln_id)
