"""CISA Known Exploited Vulnerabilities (KEV) tools."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

router = APIRouter(prefix="/kev", tags=["kev"])
_cache = TTLCache(ttl_seconds=3600)


class KevEntry(BaseModel):
    cveID: str
    vendorProject: str | None = None
    product: str | None = None
    vulnerabilityName: str | None = None
    dateAdded: str | None = None
    shortDescription: str | None = None
    requiredAction: str | None = None
    dueDate: str | None = None
    knownRansomwareCampaignUse: str | None = None
    notes: str | None = None


async def _fetch_catalog() -> dict[str, Any]:
    cached = await _cache.get("catalog")
    if cached is not None:
        return cached
    # The KEV catalog is a single 1-2 MB JSON; CISA occasionally answers
    # 502/503 during edge cache rotations, so we retry transient failures
    # via the shared backoff helper.
    response = await request_with_retry("GET", KEV_URL)
    response.raise_for_status()
    data = response.json()
    await _cache.set("catalog", data)
    return data


async def _kev_lookup(cve_id: str) -> KevEntry | None:
    catalog = await _fetch_catalog()
    target = cve_id.strip().upper()
    for item in catalog.get("vulnerabilities", []):
        if item.get("cveID", "").upper() == target:
            return KevEntry(**item)
    return None


async def _kev_search(
    since_days: int | None = None,
    vendor: str | None = None,
    ransomware_only: bool = False,
    limit: int = 50,
) -> list[KevEntry]:
    catalog = await _fetch_catalog()
    cutoff: date | None = None
    if since_days is not None:
        cutoff = datetime.now(UTC).date() - timedelta(days=since_days)

    results: list[KevEntry] = []
    for item in catalog.get("vulnerabilities", []):
        if cutoff is not None:
            added = item.get("dateAdded")
            try:
                if not added or date.fromisoformat(added) < cutoff:
                    continue
            except ValueError:
                continue
        if vendor and vendor.lower() not in (item.get("vendorProject") or "").lower():
            continue
        if ransomware_only and (item.get("knownRansomwareCampaignUse") or "").lower() != "known":
            continue
        results.append(KevEntry(**item))
        if len(results) >= limit:
            break
    return results


# --- REST (OpenAPI for Security Copilot) -------------------------------------


@router.get(
    "/lookup",
    response_model=KevEntry | None,
    summary="Look up a single CVE in the CISA KEV catalog",
    description=(
        "Returns the CISA Known Exploited Vulnerabilities entry for a CVE, or null "
        "if the CVE is not present in the catalog.\n\n"
        "#ExamplePrompts\n"
        "- Is CVE-2024-3400 in the CISA KEV catalog?\n"
        "- Has CVE-2023-23397 been exploited in the wild?\n"
        "- Tell me everything CISA knows about CVE-2021-44228."
    ),
)
async def kev_lookup_endpoint(
    cve_id: str = Query(..., examples=["CVE-2024-3400"]),
) -> KevEntry | None:
    return await _kev_lookup(cve_id)


@router.get(
    "/search",
    response_model=list[KevEntry],
    summary="Search the CISA KEV catalog",
    description=(
        "Filter the CISA Known Exploited Vulnerabilities catalog by recency, vendor, "
        "and known ransomware usage.\n\n"
        "#ExamplePrompts\n"
        "- Show CISA KEV entries added in the last 30 days.\n"
        "- List Microsoft vulnerabilities in the KEV catalog.\n"
        "- Which KEV vulnerabilities are known to be used in ransomware campaigns?"
    ),
)
async def kev_search_endpoint(
    since_days: int | None = Query(
        None, ge=1, le=3650, description="Only entries added in the last N days."
    ),
    vendor: str | None = Query(
        None, description="Case-insensitive substring match on vendorProject."
    ),
    ransomware_only: bool = Query(
        False, description="Only return entries with known ransomware usage."
    ),
    limit: int = Query(50, ge=1, le=500),
) -> list[KevEntry]:
    return await _kev_search(
        since_days=since_days,
        vendor=vendor,
        ransomware_only=ransomware_only,
        limit=limit,
    )


# --- MCP ---------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="kev_lookup",
        description=(
            "Look up a single CVE in the CISA Known Exploited Vulnerabilities (KEV) catalog."
        ),
    )
    async def kev_lookup_mcp(cve_id: str) -> dict[str, Any] | None:
        entry = await _kev_lookup(cve_id)
        return entry.model_dump() if entry else None

    @mcp.tool(
        name="kev_search",
        description=(
            "Search the CISA KEV catalog. Filter by recency (since_days), vendor substring, "
            "or ransomware-only. Returns up to `limit` entries."
        ),
    )
    async def kev_search_mcp(
        since_days: int | None = None,
        vendor: str | None = None,
        ransomware_only: bool = False,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        entries = await _kev_search(
            since_days=since_days, vendor=vendor, ransomware_only=ransomware_only, limit=limit
        )
        return [e.model_dump() for e in entries]
