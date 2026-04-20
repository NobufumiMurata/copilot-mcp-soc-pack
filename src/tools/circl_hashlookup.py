"""CIRCL hashlookup — NSRL-based known-file lookup.

Docs: https://hashlookup.circl.lu/

A single GET endpoint per algorithm:

- ``GET https://hashlookup.circl.lu/lookup/md5/{md5}``
- ``GET https://hashlookup.circl.lu/lookup/sha1/{sha1}``
- ``GET https://hashlookup.circl.lu/lookup/sha256/{sha256}``

200 = the hash is known to NSRL / the hashlookup database (typically a
benign system file). 404 = unknown. We translate 404 to a structured
``{"known": false, ...}`` response so downstream agents have a uniform
shape to reason over (in SOC workflows "this hash is NOT a known
benign file" is the actionable signal).

The service is unauthenticated and free; we still cache aggressively
(NSRL hashes don't change).
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from fastmcp import FastMCP
from pydantic import BaseModel

from src.common.http import TTLCache, request_with_retry

CIRCL_BASE = "https://hashlookup.circl.lu/lookup"

router = APIRouter(prefix="/circl", tags=["circl"])
# NSRL is updated quarterly at most; cache for a day.
_cache = TTLCache(ttl_seconds=86400)

HashAlgo = Literal["md5", "sha1", "sha256"]
_EXPECTED_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


class CirclHashResult(BaseModel):
    algo: HashAlgo
    hash: str
    known: bool
    metadata: dict[str, Any] | None = None


def _validate_hash(algo: HashAlgo, value: str) -> str:
    cleaned = value.strip().lower()
    expected = _EXPECTED_HEX_LEN.get(algo)
    if expected is None:
        raise HTTPException(
            status_code=400, detail=f"algo must be md5/sha1/sha256, got {algo!r}."
        )
    if len(cleaned) != expected or any(c not in "0123456789abcdef" for c in cleaned):
        raise HTTPException(
            status_code=400,
            detail=f"{algo} hash must be exactly {expected} hexadecimal characters.",
        )
    return cleaned


async def _lookup_hash(algo: HashAlgo, hash_value: str) -> CirclHashResult:
    cleaned = _validate_hash(algo, hash_value)
    cache_key = f"{algo}|{cleaned}"
    cached = await _cache.get(cache_key)
    if cached is not None:
        return CirclHashResult(**cached)

    response = await request_with_retry("GET", f"{CIRCL_BASE}/{algo}/{cleaned}")
    if response.status_code == 404:
        result = CirclHashResult(algo=algo, hash=cleaned, known=False)
        await _cache.set(cache_key, result.model_dump())
        return result
    if response.status_code == 429:
        raise HTTPException(
            status_code=429, detail="CIRCL hashlookup rate limit reached. Retry shortly."
        )
    if response.status_code >= 500:
        raise HTTPException(
            status_code=503, detail="CIRCL hashlookup upstream is currently unavailable."
        )
    response.raise_for_status()

    payload = response.json() or {}
    result = CirclHashResult(algo=algo, hash=cleaned, known=True, metadata=payload)
    await _cache.set(cache_key, result.model_dump())
    return result


# --- REST -------------------------------------------------------------------


@router.get(
    "/hashlookup/md5/{hash_value}",
    response_model=CirclHashResult,
    summary="Look up an MD5 hash in CIRCL hashlookup (NSRL)",
    description=(
        "Returns whether the MD5 hash is present in the CIRCL hashlookup database "
        "(primarily NSRL known-good software). ``known=true`` means the file is a "
        "known, typically benign, system file. ``known=false`` is the actionable "
        "signal in SOC workflows.\n\n"
        "#ExamplePrompts\n"
        "- Is MD5 8ed4b4ed952526d89899e723f3488de4 a known benign file?\n"
        "- Check the hash 8ed4b4ed952526d89899e723f3488de4 against NSRL.\n"
        "- Look up MD5 d41d8cd98f00b204e9800998ecf8427e in CIRCL hashlookup."
    ),
)
async def circl_md5_endpoint(hash_value: str) -> CirclHashResult:
    return await _lookup_hash("md5", hash_value)


@router.get(
    "/hashlookup/sha1/{hash_value}",
    response_model=CirclHashResult,
    summary="Look up a SHA1 hash in CIRCL hashlookup (NSRL)",
    description=(
        "Returns whether the SHA1 hash is present in the CIRCL hashlookup database "
        "(primarily NSRL known-good software).\n\n"
        "#ExamplePrompts\n"
        "- Is SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709 known to NSRL?\n"
        "- Check this SHA1 against CIRCL hashlookup.\n"
        "- Is the SHA1 of this binary a known benign file?"
    ),
)
async def circl_sha1_endpoint(hash_value: str) -> CirclHashResult:
    return await _lookup_hash("sha1", hash_value)


@router.get(
    "/hashlookup/sha256/{hash_value}",
    response_model=CirclHashResult,
    summary="Look up a SHA256 hash in CIRCL hashlookup (NSRL)",
    description=(
        "Returns whether the SHA256 hash is present in the CIRCL hashlookup database "
        "(primarily NSRL known-good software).\n\n"
        "#ExamplePrompts\n"
        "- Is SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 known?\n"
        "- Check this SHA256 against NSRL via CIRCL hashlookup.\n"
        "- Is this file SHA256 in the CIRCL known-good database?"
    ),
)
async def circl_sha256_endpoint(hash_value: str) -> CirclHashResult:
    return await _lookup_hash("sha256", hash_value)


# --- MCP --------------------------------------------------------------------


def register_mcp_tools(mcp: FastMCP) -> None:
    @mcp.tool(
        name="circl_hashlookup_md5",
        description=(
            "Look up an MD5 hash in CIRCL hashlookup (NSRL known-good database). "
            "Returns ``known=true`` for known benign files, ``known=false`` if not "
            "indexed (the latter is the SOC-actionable signal)."
        ),
    )
    async def circl_md5_mcp(hash_value: str) -> dict[str, Any]:
        return (await _lookup_hash("md5", hash_value)).model_dump()

    @mcp.tool(
        name="circl_hashlookup_sha1",
        description=(
            "Look up a SHA1 hash in CIRCL hashlookup (NSRL known-good database)."
        ),
    )
    async def circl_sha1_mcp(hash_value: str) -> dict[str, Any]:
        return (await _lookup_hash("sha1", hash_value)).model_dump()

    @mcp.tool(
        name="circl_hashlookup_sha256",
        description=(
            "Look up a SHA256 hash in CIRCL hashlookup (NSRL known-good database)."
        ),
    )
    async def circl_sha256_mcp(hash_value: str) -> dict[str, Any]:
        return (await _lookup_hash("sha256", hash_value)).model_dump()
