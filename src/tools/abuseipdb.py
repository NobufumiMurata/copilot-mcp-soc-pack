"""AbuseIPDB v2 check endpoint.

Docs: https://docs.abuseipdb.com/#check-endpoint

A free API key (1000 requests/day) is required and sent via the ``Key``
header. Set the ``ABUSEIPDB_API_KEY`` environment variable.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_API_KEY_ENV = "ABUSEIPDB_API_KEY"

router = APIRouter(prefix="/abuseipdb", tags=["abuseipdb"])
_cache = TTLCache(ttl_seconds=1800)


class AbuseIPDBCheck(BaseModel):
    ipAddress: str
    abuseConfidenceScore: int | None = None
    countryCode: str | None = None
    usageType: str | None = None
    isp: str | None = None
    domain: str | None = None
    totalReports: int | None = None
    numDistinctUsers: int | None = None
    lastReportedAt: str | None = None
    isPublic: bool | None = None
    isWhitelisted: bool | None = None


async def _check(ip: str, max_age_in_days: int) -> AbuseIPDBCheck:
    key = os.environ.get(ABUSEIPDB_API_KEY_ENV)
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                "AbuseIPDB requires a free API key. "
                "Set ABUSEIPDB_API_KEY (register at https://www.abuseipdb.com/register)."
            ),
        )

    target = ip.strip()
    cache_key = f"{target}|{max_age_in_days}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return AbuseIPDBCheck(**cached)

    # 5xx and 429 are transient; retry via the shared backoff helper. After
    # the retry budget is exhausted the final response (including 429) is
    # returned and translated below.
    response = await request_with_retry(
        "GET",
        ABUSEIPDB_CHECK_URL,
        params={"ipAddress": target, "maxAgeInDays": max_age_in_days},
        headers={"Key": key, "Accept": "application/json"},
    )
    if response.status_code == 401:
        raise HTTPException(
            status_code=401,
            detail="AbuseIPDB rejected the API key. Verify ABUSEIPDB_API_KEY.",
        )
    if response.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail="AbuseIPDB rate limit reached (1000 req/day on free tier).",
        )
    response.raise_for_status()

    data = response.json().get("data", {}) or {}
    result = AbuseIPDBCheck(
        ipAddress=data.get("ipAddress", target),
        abuseConfidenceScore=data.get("abuseConfidenceScore"),
        countryCode=data.get("countryCode"),
        usageType=data.get("usageType"),
        isp=data.get("isp"),
        domain=data.get("domain"),
        totalReports=data.get("totalReports"),
        numDistinctUsers=data.get("numDistinctUsers"),
        lastReportedAt=data.get("lastReportedAt"),
        isPublic=data.get("isPublic"),
        isWhitelisted=data.get("isWhitelisted"),
    )
    await _cache.set(cache_key, result.model_dump())
    return result


# --- REST -------------------------------------------------------------------


@router.get(
    "/check",
    response_model=AbuseIPDBCheck,
    summary="Check an IP reputation via AbuseIPDB",
    description=(
        "Returns AbuseIPDB v2 check results: abuseConfidenceScore (0-100), "
        "country, ISP, usage type, number of reports and last report timestamp.\n\n"
        "#ExamplePrompts\n"
        "- What is the AbuseIPDB reputation of 1.2.3.4?\n"
        "- Is 8.8.8.8 reported as malicious on AbuseIPDB?\n"
        "- Show me the abuse confidence score and report count for 45.155.205.233."
    ),
)
async def abuseipdb_check_endpoint(
    ip: str = Query(..., examples=["1.2.3.4"]),
    max_age_in_days: int = Query(
        90, ge=1, le=365, description="Only consider reports newer than N days."
    ),
) -> AbuseIPDBCheck:
    return await _check(ip, max_age_in_days)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="abuseipdb_check",
        description=(
            "Check an IP's reputation on AbuseIPDB. Returns abuseConfidenceScore "
            "(0-100), country, ISP, usage type, total reports and last report time."
        ),
    )
    async def abuseipdb_check_mcp(ip: str, max_age_in_days: int = 90) -> dict[str, Any]:
        return (await _check(ip, max_age_in_days)).model_dump()
