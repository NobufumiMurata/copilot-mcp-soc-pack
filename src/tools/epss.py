"""FIRST EPSS (Exploit Prediction Scoring System) tools."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, get_client

EPSS_URL = "https://api.first.org/data/v1/epss"

router = APIRouter(prefix="/epss", tags=["epss"])
_cache = TTLCache(ttl_seconds=1800)


class EpssScore(BaseModel):
    cve: str
    epss: float
    percentile: float
    date: str | None = None


async def _epss_score(cve_ids: list[str]) -> list[EpssScore]:
    if not cve_ids:
        return []
    key = ",".join(sorted({c.strip().upper() for c in cve_ids if c.strip()}))
    if not key:
        return []
    cached = await _cache.get(key)
    if cached is not None:
        return cached

    client = await get_client()
    response = await client.get(EPSS_URL, params={"cve": key})
    response.raise_for_status()
    payload = response.json()

    results: list[EpssScore] = []
    for row in payload.get("data", []):
        try:
            results.append(
                EpssScore(
                    cve=row["cve"],
                    epss=float(row["epss"]),
                    percentile=float(row["percentile"]),
                    date=row.get("date"),
                )
            )
        except (KeyError, ValueError):
            continue
    await _cache.set(key, results)
    return results


# --- REST --------------------------------------------------------------------


@router.get(
    "/score",
    response_model=list[EpssScore],
    summary="Get EPSS scores for one or more CVEs",
    description=(
        "Returns EPSS (Exploit Prediction Scoring System) scores and percentiles "
        "from FIRST for the supplied CVE IDs."
    ),
)
async def epss_score_endpoint(
    cve_ids: list[str] = Query(..., alias="cve", examples=[["CVE-2024-3400"]]),
) -> list[EpssScore]:
    return await _epss_score(cve_ids)


# --- MCP ---------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="epss_score",
        description=(
            "Look up FIRST EPSS (Exploit Prediction Scoring System) scores for one or "
            "more CVE IDs. Scores are between 0 and 1; higher scores predict higher "
            "probability of in-the-wild exploitation within 30 days."
        ),
    )
    async def epss_score_mcp(cve_ids: list[str]) -> list[dict[str, Any]]:
        scores = await _epss_score(cve_ids)
        return [s.model_dump() for s in scores]
