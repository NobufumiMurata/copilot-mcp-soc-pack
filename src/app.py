"""FastAPI + FastMCP application.

Exposes all SOC tools simultaneously as:
- REST endpoints + OpenAPI schema  (for Microsoft Security Copilot custom plugins)
- MCP server over Streamable HTTP   (for VS Code / Claude Desktop / any MCP client)
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastmcp import FastMCP

from src import __version__
from src.tools import attack, epss, kev

API_KEY_ENV = "MCP_SOC_PACK_API_KEY"


def _require_api_key(request: Request) -> None:
    """Optional API-key gate. If env var unset, auth is disabled (dev mode)."""
    expected = os.environ.get(API_KEY_ENV)
    if not expected:
        return
    provided = request.headers.get("X-API-Key")
    if provided != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Place for warmup hooks (e.g. pre-fetch KEV/ATT&CK caches) in future iterations.
    yield


app = FastAPI(
    title="Copilot MCP SOC Pack",
    version=__version__,
    description=(
        "Community SOC Pack for Microsoft Security Copilot. Bundles free security APIs "
        "(CISA KEV, FIRST EPSS, MITRE ATT&CK, Abuse.ch, GreyNoise, AbuseIPDB, crt.sh, "
        "ransomware.live) behind a single OpenAPI + MCP surface."
    ),
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health", tags=["meta"], summary="Liveness probe")
def health() -> dict[str, str]:
    """Simple liveness probe used by Container Apps and Kubernetes."""
    return {"status": "ok", "version": __version__}


# --- Tool routers ------------------------------------------------------------
app.include_router(kev.router, dependencies=[Depends(_require_api_key)])
app.include_router(epss.router, dependencies=[Depends(_require_api_key)])
app.include_router(attack.router, dependencies=[Depends(_require_api_key)])


# --- MCP server --------------------------------------------------------------
# FastMCP mounts a Streamable-HTTP transport at /mcp/. Each @mcp.tool wraps the
# same async function that the REST router exposes, so we maintain one source
# of truth per capability.
mcp = FastMCP(name="copilot-mcp-soc-pack")

kev.register_mcp_tools(mcp)
epss.register_mcp_tools(mcp)
attack.register_mcp_tools(mcp)

app.mount("/mcp", mcp.http_app())
