"""GreyNoise Community API tool.

The Community endpoint classifies an IPv4 as internet-scan noise (``noise``),
known-benign service (``riot``), or targeted. A free key is required and
must be sent via the ``key`` HTTP header.

Docs: https://docs.greynoise.io/reference/get_v3-community-ip
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/"
GREYNOISE_API_KEY_ENV = "GREYNOISE_API_KEY"

router = APIRouter(prefix="/greynoise", tags=["greynoise"])
_cache = TTLCache(ttl_seconds=3600)


class GreyNoiseClassification(BaseModel):
    ip: str
    noise: bool | None = None
    riot: bool | None = None
    classification: str | None = None
    name: str | None = None
    link: str | None = None
    last_seen: str | None = None
    message: str | None = None


async def _classify(ip: str) -> GreyNoiseClassification:
    key = os.environ.get(GREYNOISE_API_KEY_ENV)
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                "GreyNoise Community requires a free API key. "
                "Set GREYNOISE_API_KEY (register at https://viz.greynoise.io/signup)."
            ),
        )

    target = ip.strip()
    cached = await _cache.get(target)
    if cached is not None:
        return GreyNoiseClassification(**cached)

    # 5xx and 429 are transient; retry via the shared backoff helper. After
    # the retry budget is exhausted the final response (including 429) is
    # returned and translated below.
    response = await request_with_retry(
        "GET",
        GREYNOISE_COMMUNITY_URL + target,
        headers={"key": key, "Accept": "application/json"},
    )
    if response.status_code == 401:
        raise HTTPException(
            status_code=401,
            detail="GreyNoise rejected the API key. Verify GREYNOISE_API_KEY.",
        )
    if response.status_code == 429:
        raise HTTPException(
            status_code=429,
            detail="GreyNoise Community rate limit reached. Retry later.",
        )
    # 404 = IP not observed; GreyNoise returns a JSON body explaining the miss.
    if response.status_code not in (200, 404):
        response.raise_for_status()

    payload = response.json()
    result = GreyNoiseClassification(
        ip=payload.get("ip", target),
        noise=payload.get("noise"),
        riot=payload.get("riot"),
        classification=payload.get("classification"),
        name=payload.get("name"),
        link=payload.get("link"),
        last_seen=payload.get("last_seen"),
        message=payload.get("message"),
    )
    await _cache.set(target, result.model_dump())
    return result


# --- REST -------------------------------------------------------------------


@router.get(
    "/classify",
    response_model=GreyNoiseClassification,
    summary="Classify an IP via GreyNoise Community",
    description=(
        "Returns GreyNoise Community classification for an IPv4: whether it is "
        "internet-scan noise, a known-benign service (RIOT), and a human-readable "
        "name and link when available.\n\n"
        "#ExamplePrompts\n"
        "- Is 8.8.8.8 a known benign service on GreyNoise?\n"
        "- Classify 45.155.205.233 with GreyNoise Community.\n"
        "- Is the IP 192.0.2.1 internet-scan noise?"
    ),
)
async def greynoise_classify_endpoint(
    ip: str = Query(..., examples=["8.8.8.8"]),
) -> GreyNoiseClassification:
    return await _classify(ip)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="greynoise_classify",
        description=(
            "Classify an IP address using GreyNoise Community. Tells you if the IP "
            "is internet-scan noise, a RIOT (benign) service, or targeted."
        ),
    )
    async def greynoise_classify_mcp(ip: str) -> dict[str, Any]:
        return (await _classify(ip)).model_dump()
