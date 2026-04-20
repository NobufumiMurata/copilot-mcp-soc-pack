"""MITRE ATT&CK technique lookup.

Loads the Enterprise ATT&CK STIX 2.1 bundle from the public MITRE CTI repo
on first call and caches it in memory.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

router = APIRouter(prefix="/attack", tags=["attack"])
# ATT&CK bundle is updated a few times a year; cache for 24h.
_cache = TTLCache(ttl_seconds=86400)


class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    tactics: list[str] = []
    description: str | None = None
    platforms: list[str] = []
    detection: str | None = None
    is_subtechnique: bool = False
    url: str | None = None


async def _load_bundle() -> dict[str, Any]:
    cached = await _cache.get("bundle")
    if cached is not None:
        return cached
    # The MITRE CTI bundle is a ~30 MB JSON served from raw.githubusercontent.com,
    # which occasionally answers 5xx during edge cache rotations. Retry transient
    # failures via the shared backoff helper.
    response = await request_with_retry("GET", ATTACK_URL)
    response.raise_for_status()
    data = response.json()
    await _cache.set("bundle", data)
    return data


def _obj_to_technique(obj: dict[str, Any]) -> AttackTechnique | None:
    if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None
    external_refs = obj.get("external_references", [])
    mitre_ref = next((r for r in external_refs if r.get("source_name") == "mitre-attack"), None)
    if not mitre_ref or not mitre_ref.get("external_id"):
        return None
    tactics = [
        phase.get("phase_name")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
    ]
    return AttackTechnique(
        technique_id=mitre_ref["external_id"],
        name=obj.get("name", ""),
        tactics=tactics,
        description=obj.get("description"),
        platforms=obj.get("x_mitre_platforms", []) or [],
        detection=obj.get("x_mitre_detection"),
        is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
        url=mitre_ref.get("url"),
    )


async def _attack_technique(technique_id: str) -> AttackTechnique | None:
    target = technique_id.strip().upper()
    if not TECHNIQUE_ID_RE.match(target):
        raise HTTPException(status_code=400, detail=f"Invalid technique ID: {technique_id}")
    bundle = await _load_bundle()
    for obj in bundle.get("objects", []):
        technique = _obj_to_technique(obj)
        if technique and technique.technique_id.upper() == target:
            return technique
    return None


async def _attack_search(query: str, limit: int = 20) -> list[AttackTechnique]:
    q = query.strip().lower()
    if not q:
        return []
    bundle = await _load_bundle()
    results: list[AttackTechnique] = []
    for obj in bundle.get("objects", []):
        technique = _obj_to_technique(obj)
        if not technique:
            continue
        haystack = " ".join(
            [
                technique.technique_id,
                technique.name,
                technique.description or "",
                " ".join(technique.tactics),
                " ".join(technique.platforms),
            ]
        ).lower()
        if q in haystack:
            # Truncate description for search payload size.
            if technique.description and len(technique.description) > 500:
                technique = technique.model_copy(
                    update={"description": technique.description[:500] + "…"}
                )
            results.append(technique)
            if len(results) >= limit:
                break
    return results


# --- REST --------------------------------------------------------------------


@router.get(
    "/technique",
    response_model=AttackTechnique | None,
    summary="Get a MITRE ATT&CK Enterprise technique by ID",
    description=(
        "Look up a technique or sub-technique (e.g. T1566 or T1566.001).\n\n"
        "#ExamplePrompts\n"
        "- Summarize MITRE ATT&CK technique T1566.001.\n"
        "- What tactics does T1059 belong to?\n"
        "- Describe ATT&CK technique T1078 and its detection guidance."
    ),
)
async def attack_technique_endpoint(
    technique_id: str = Query(..., examples=["T1566.001"]),
) -> AttackTechnique | None:
    return await _attack_technique(technique_id)


@router.get(
    "/search",
    response_model=list[AttackTechnique],
    summary="Search MITRE ATT&CK Enterprise techniques",
    description=(
        "Case-insensitive substring match across technique ID, name, description, "
        "tactics, and platforms.\n\n"
        "#ExamplePrompts\n"
        "- Find ATT&CK techniques related to phishing.\n"
        "- Search MITRE ATT&CK for credential access techniques.\n"
        "- Which ATT&CK techniques target Linux platforms?"
    ),
)
async def attack_search_endpoint(
    query: str = Query(..., min_length=2, examples=["phishing"]),
    limit: int = Query(20, ge=1, le=100),
) -> list[AttackTechnique]:
    return await _attack_search(query, limit=limit)


# --- MCP ---------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="attack_technique",
        description=(
            "Look up a MITRE ATT&CK Enterprise technique or sub-technique by ID "
            "(e.g. T1566 or T1566.001). Returns tactics, platforms, description, "
            "and detection guidance."
        ),
    )
    async def attack_technique_mcp(technique_id: str) -> dict[str, Any] | None:
        technique = await _attack_technique(technique_id)
        return technique.model_dump() if technique else None

    @mcp.tool(
        name="attack_search",
        description="Search MITRE ATT&CK Enterprise techniques by free-text query.",
    )
    async def attack_search_mcp(query: str, limit: int = 20) -> list[dict[str, Any]]:
        items = await _attack_search(query, limit=limit)
        return [i.model_dump() for i in items]
