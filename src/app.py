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
from fastapi.openapi.utils import get_openapi
from fastmcp import FastMCP

from src import __version__
from src.common.openapi_compat import downgrade_to_3_0_1
from src.tools import (
    abusech,
    abuseipdb,
    attack,
    crtsh,
    epss,
    greynoise,
    hibp,
    kev,
    otx,
    ransomwarelive,
)

API_KEY_ENV = "MCP_SOC_PACK_API_KEY"


def _require_api_key(request: Request) -> None:
    """Optional API-key gate. If env var unset, auth is disabled (dev mode).

    Accepts either ``X-API-Key: <key>`` or ``Authorization: Bearer <key>``.
    The Bearer form is required because Microsoft Security Copilot's OpenAI
    plugin loader only supports ``authorization_type: bearer`` for custom
    plugins (see https://learn.microsoft.com/en-us/copilot/security/custom-plugins).
    """
    expected = os.environ.get(API_KEY_ENV)
    if not expected:
        return
    provided = request.headers.get("X-API-Key")
    if not provided:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            provided = auth.split(" ", 1)[1].strip()
    if provided != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key (X-API-Key or Authorization: Bearer).",
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


# --- OpenAPI 3.0.1 override --------------------------------------------------
# Microsoft Security Copilot only ingests OpenAPI 3.0 / 3.0.1 specs. FastAPI
# emits 3.1 by default, so we generate the spec once, downgrade the known
# incompatibilities (null-anyOf pattern, version string) and cache the result.
def _custom_openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    if not schema.get("components", {}).get("securitySchemes"):
        schema.setdefault("components", {})["securitySchemes"] = {
            "BearerAuth": {"type": "http", "scheme": "bearer"}
        }
        schema["security"] = [{"BearerAuth": []}]
    downgrade_to_3_0_1(schema)
    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi  # type: ignore[assignment]


# --- Tool routers ------------------------------------------------------------
app.include_router(kev.router, dependencies=[Depends(_require_api_key)])
app.include_router(epss.router, dependencies=[Depends(_require_api_key)])
app.include_router(attack.router, dependencies=[Depends(_require_api_key)])
app.include_router(abusech.router, dependencies=[Depends(_require_api_key)])
app.include_router(greynoise.router, dependencies=[Depends(_require_api_key)])
app.include_router(abuseipdb.router, dependencies=[Depends(_require_api_key)])
app.include_router(crtsh.router, dependencies=[Depends(_require_api_key)])
app.include_router(ransomwarelive.router, dependencies=[Depends(_require_api_key)])
app.include_router(otx.router, dependencies=[Depends(_require_api_key)])
app.include_router(hibp.router, dependencies=[Depends(_require_api_key)])


# --- MCP server --------------------------------------------------------------
# FastMCP mounts a Streamable-HTTP transport at /mcp/. Each @mcp.tool wraps the
# same async function that the REST router exposes, so we maintain one source
# of truth per capability.
mcp = FastMCP(name="copilot-mcp-soc-pack")

kev.register_mcp_tools(mcp)
epss.register_mcp_tools(mcp)
abusech.register_mcp_tools(mcp)
attack.register_mcp_tools(mcp)
greynoise.register_mcp_tools(mcp)
abuseipdb.register_mcp_tools(mcp)
crtsh.register_mcp_tools(mcp)
ransomwarelive.register_mcp_tools(mcp)
otx.register_mcp_tools(mcp)
hibp.register_mcp_tools(mcp)

app.mount("/mcp", mcp.http_app())
