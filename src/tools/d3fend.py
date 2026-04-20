"""MITRE D3FEND — defensive technique mappings to ATT&CK.

Source: https://d3fend.mitre.org/

D3FEND publishes a single large SPARQL-results JSON file that maps every
ATT&CK (offensive) technique to the D3FEND (defensive) techniques that
mitigate it, along with the digital artifacts each side touches. We
download that file once, build two in-memory indexes, and serve lookups
from them. The file is ~45 MB and updates infrequently, so we cache for
a week.

The upstream JSON shape is the standard SPARQL ``SELECT`` results:

.. code-block:: json

    {
      "head": {"vars": ["off_tech_id", "def_tech_label", "..."]},
      "results": {"bindings": [
        {"off_tech_id": {"type": "literal", "value": "T1550.001"},
         "def_tech_label": {"type": "literal", "value": "Token Binding"},
         "...": {...}}
      ]}
    }

We flatten each binding to a plain ``{var: value}`` dict so downstream
agents do not have to reason over the SPARQL envelope.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import request_with_retry

# Pinned snapshot URL. The full mappings file is regenerated on every
# D3FEND release; pin a known-good endpoint to keep behaviour stable.
D3FEND_MAPPINGS_URL = (
    "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
)

# 7 days. D3FEND ships new mappings with each release (months apart).
_TTL_SECONDS = 7 * 86400

router = APIRouter(prefix="/d3fend", tags=["d3fend"])


class D3fendDefenseEntry(BaseModel):
    """One flattened SPARQL binding row."""

    # Use a plain dict[str, str] so we don't have to enumerate the ~22
    # column names the upstream query exposes (and they may evolve).
    fields: dict[str, str]


class D3fendDefensesForAttackResult(BaseModel):
    attack_technique_id: str
    count: int
    defenses: list[dict[str, str]]


class D3fendAttacksForDefenseResult(BaseModel):
    defense_label: str
    count: int
    attacks: list[dict[str, str]]


# --- mappings cache ---------------------------------------------------------

_state_lock = asyncio.Lock()
_state: dict[str, Any] = {
    "loaded_at": 0.0,
    "by_attack": {},  # attack_technique_id -> list[flat binding]
    "by_defense": {},  # def_tech_label (lower) -> list[flat binding]
}


def _flatten_binding(binding: dict[str, Any]) -> dict[str, str]:
    """Collapse ``{var: {type, value}}`` to ``{var: value}``."""
    out: dict[str, str] = {}
    for key, cell in binding.items():
        if isinstance(cell, dict) and "value" in cell:
            out[key] = str(cell["value"])
    return out


async def _load_mappings(force: bool = False) -> None:
    """Download the mappings file once per TTL and rebuild the indexes."""
    async with _state_lock:
        now = time.time()
        if not force and (now - _state["loaded_at"]) < _TTL_SECONDS and _state["by_attack"]:
            return

        try:
            response = await request_with_retry(
                "GET",
                D3FEND_MAPPINGS_URL,
                timeout=httpx.Timeout(60.0, connect=10.0),
            )
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Failed to fetch D3FEND mappings: {exc}",
            ) from exc

        if response.status_code >= 500:
            raise HTTPException(
                status_code=503, detail="D3FEND upstream is currently unavailable."
            )
        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"D3FEND mappings fetch returned HTTP {response.status_code}.",
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"D3FEND mappings response was not valid JSON: {exc}",
            ) from exc

        bindings = payload.get("results", {}).get("bindings", [])
        by_attack: dict[str, list[dict[str, str]]] = {}
        by_defense: dict[str, list[dict[str, str]]] = {}
        for raw in bindings:
            flat = _flatten_binding(raw)
            attack_id = flat.get("off_tech_id")
            if attack_id:
                by_attack.setdefault(attack_id, []).append(flat)
            defense_label = flat.get("def_tech_label")
            if defense_label:
                by_defense.setdefault(defense_label.lower(), []).append(flat)

        _state["by_attack"] = by_attack
        _state["by_defense"] = by_defense
        _state["loaded_at"] = now


async def _defenses_for_attack(attack_technique_id: str) -> D3fendDefensesForAttackResult:
    cleaned = attack_technique_id.strip()
    if not cleaned or not cleaned.startswith("T"):
        raise HTTPException(
            status_code=400,
            detail="attack_technique_id must be an ATT&CK technique id like T1059 or T1550.001.",
        )
    await _load_mappings()
    matches = _state["by_attack"].get(cleaned, [])
    return D3fendDefensesForAttackResult(
        attack_technique_id=cleaned,
        count=len(matches),
        defenses=matches,
    )


async def _attacks_for_defense(defense_label: str) -> D3fendAttacksForDefenseResult:
    cleaned = defense_label.strip()
    if not cleaned:
        raise HTTPException(status_code=400, detail="defense_label must be non-empty.")
    await _load_mappings()
    matches = _state["by_defense"].get(cleaned.lower(), [])
    return D3fendAttacksForDefenseResult(
        defense_label=cleaned,
        count=len(matches),
        attacks=matches,
    )


# --- REST -------------------------------------------------------------------


@router.get(
    "/defenses_for_attack/{attack_technique_id}",
    response_model=D3fendDefensesForAttackResult,
    summary="List MITRE D3FEND defenses that counter a given ATT&CK technique",
    description=(
        "Given a MITRE ATT&CK technique id (e.g. ``T1059`` or ``T1550.001``), "
        "returns the D3FEND defensive techniques mapped to it, including the "
        "defensive tactic, the digital artifact each defense touches, and the "
        "relationship verb (``strengthens``, ``isolates``, ``analyzes`` ...). "
        "Powered by the D3FEND full mappings JSON, cached for 7 days.\n\n"
        "#ExamplePrompts\n"
        "- What D3FEND defenses counter MITRE ATT&CK T1059?\n"
        "- Show defensive techniques mapped to T1550.001.\n"
        "- Which D3FEND techniques mitigate ATT&CK T1486 (Data Encrypted for Impact)?"
    ),
)
async def d3fend_defenses_for_attack_endpoint(
    attack_technique_id: str,
) -> D3fendDefensesForAttackResult:
    return await _defenses_for_attack(attack_technique_id)


@router.get(
    "/attacks_for_defense/{defense_label}",
    response_model=D3fendAttacksForDefenseResult,
    summary="List MITRE ATT&CK techniques countered by a given D3FEND defense",
    description=(
        "Reverse mapping: given a D3FEND defensive technique label "
        "(e.g. ``Token Binding`` or ``Process Spawn Analysis``), returns the "
        "MITRE ATT&CK techniques that defense is mapped against. Match is "
        "case-insensitive on the exact D3FEND label.\n\n"
        "#ExamplePrompts\n"
        "- What ATT&CK techniques does Token Binding mitigate?\n"
        "- List the offensive techniques covered by Process Spawn Analysis.\n"
        "- Which ATT&CK entries are countered by Credential Hardening?"
    ),
)
async def d3fend_attacks_for_defense_endpoint(
    defense_label: str,
) -> D3fendAttacksForDefenseResult:
    return await _attacks_for_defense(defense_label)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="d3fend_defenses_for_attack",
        description=(
            "Look up MITRE D3FEND defensive techniques mapped to a given MITRE "
            "ATT&CK technique id (e.g. T1059, T1550.001). Returns the defensive "
            "tactic, defense label, digital artifact, and relationship verb for "
            "each mapping. Use this to answer 'what defenses counter ATT&CK X?'."
        ),
    )
    async def d3fend_defenses_for_attack_mcp(attack_technique_id: str) -> dict[str, Any]:
        return (await _defenses_for_attack(attack_technique_id)).model_dump()

    @mcp.tool(
        name="d3fend_attacks_for_defense",
        description=(
            "Reverse mapping: given a D3FEND defensive technique label (e.g. "
            "'Token Binding'), list the MITRE ATT&CK techniques it counters."
        ),
    )
    async def d3fend_attacks_for_defense_mcp(defense_label: str) -> dict[str, Any]:
        return (await _attacks_for_defense(defense_label)).model_dump()
