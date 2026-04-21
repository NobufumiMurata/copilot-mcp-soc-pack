"""FastAPI + FastMCP application.

Exposes all SOC tools simultaneously as:
- REST endpoints + OpenAPI schema  (for Microsoft Security Copilot custom plugins)
- MCP server over Streamable HTTP   (for VS Code / Claude Desktop / any MCP client)
"""

from __future__ import annotations

import hmac
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastmcp import FastMCP

from src import __version__
from src.common.http import get_client
from src.common.openapi_compat import downgrade_to_3_0_1
from src.tools import (
    abusech,
    abuseipdb,
    attack,
    circl_hashlookup,
    crtsh,
    d3fend,
    epss,
    greynoise,
    hibp,
    kev,
    osv,
    otx,
    ransomwarelive,
)

API_KEY_ENV = "MCP_SOC_PACK_API_KEY"
CORS_ORIGINS_ENV = "MCP_SOC_PACK_CORS_ORIGINS"


def _require_api_key(request: Request) -> None:
    """Optional API-key gate. If env var unset, auth is disabled (dev mode).

    Accepts either ``X-API-Key: <key>`` or ``Authorization: Bearer <key>``.
    The Bearer form is required because Microsoft Security Copilot's OpenAI
    plugin loader only supports ``authorization_type: bearer`` for custom
    plugins (see https://learn.microsoft.com/en-us/copilot/security/custom-plugins).

    Comparison uses :func:`hmac.compare_digest` to avoid leaking the key
    via a timing side channel.
    """
    expected = os.environ.get(API_KEY_ENV)
    if not expected:
        return
    provided = request.headers.get("X-API-Key")
    if not provided:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            provided = auth.split(" ", 1)[1].strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key (X-API-Key or Authorization: Bearer).",
        )


def _resolve_cors_origins() -> list[str]:
    """Resolve the CORS allow-list from ``MCP_SOC_PACK_CORS_ORIGINS``.

    The env var is a comma-separated list of origins. The default is an
    empty list (no browser origin allowed) which is the safest setting
    for a service that is normally called server-to-server by Microsoft
    Security Copilot or by an MCP client (which does not need CORS).

    Set ``MCP_SOC_PACK_CORS_ORIGINS=*`` to restore the previous wildcard
    behaviour for local development; do not use ``*`` in production.
    """
    raw = os.environ.get(CORS_ORIGINS_ENV, "").strip()
    if not raw:
        return []
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


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

_cors_origins = _resolve_cors_origins()
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )


@app.get("/health", tags=["meta"], summary="Liveness probe")
def health() -> dict[str, str]:
    """Cheap liveness probe used by Container Apps and Kubernetes.

    Returns immediately without touching upstreams or caches; a passing
    response only means the ASGI loop is still serving requests. For a
    deeper check that exercises an upstream call, use ``/ready``.
    """
    return {"status": "ok", "version": __version__}


@app.get("/ready", tags=["meta"], summary="Readiness probe")
async def ready() -> dict[str, Any]:
    """Readiness probe that exercises the shared HTTP client.

    Performs a lightweight call to the shared ``httpx`` client (bound to
    a static, low-cost endpoint) so that:

    - cold-start failures (DNS misconfig, TLS trust store missing, ...)
      surface as a 503 instead of a hung container; and
    - load balancers can wait for the first replica to actually be able
      to talk to the public internet before sending real traffic.

    Container Apps probes should still hit ``/health`` for liveness; use
    ``/ready`` for readiness only.
    """
    try:
        client = await get_client()
        # api.first.org is small, free, and has no rate limit on this path.
        response = await client.get("https://api.first.org/data/v1/epss?cve=CVE-2024-3400")
        upstream_ok = response.status_code < 500
    except Exception as exc:  # noqa: BLE001 - probe must not raise
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"readiness probe failed: {type(exc).__name__}",
        ) from exc
    if not upstream_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"upstream returned status={response.status_code}",
        )
    return {"status": "ready", "version": __version__}


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


app.openapi = _custom_openapi  # type: ignore[method-assign]


# --- Tool routers ------------------------------------------------------------
# Tools that require an upstream API key are only registered when their
# corresponding env var is present. This keeps the OpenAPI surface (and
# the MCP tool list) honest: Security Copilot's planner picks skills from
# the advertised OpenAPI; if a skill is advertised but always returns 503
# because no key is configured, the planner treats the whole multi-skill
# request as failed ("Couldn't complete your request"). By hiding the
# unconfigured skill we give the planner a clean menu of working tools.
import logging as _logging  # noqa: E402

_app_log = _logging.getLogger(__name__)

_KEY_GATED_TOOLS: list[tuple[str, str, Any]] = [
    ("GREYNOISE_API_KEY", "greynoise", greynoise),
    ("ABUSEIPDB_API_KEY", "abuseipdb", abuseipdb),
    ("ABUSE_CH_AUTH_KEY", "abusech (MalwareBazaar / ThreatFox / URLhaus)", abusech),
    ("OTX_API_KEY", "otx", otx),
]

app.include_router(kev.router, dependencies=[Depends(_require_api_key)])
app.include_router(epss.router, dependencies=[Depends(_require_api_key)])
app.include_router(attack.router, dependencies=[Depends(_require_api_key)])
app.include_router(crtsh.router, dependencies=[Depends(_require_api_key)])
app.include_router(ransomwarelive.router, dependencies=[Depends(_require_api_key)])
app.include_router(hibp.router, dependencies=[Depends(_require_api_key)])
app.include_router(osv.router, dependencies=[Depends(_require_api_key)])
app.include_router(circl_hashlookup.router, dependencies=[Depends(_require_api_key)])
app.include_router(d3fend.router, dependencies=[Depends(_require_api_key)])

for _env_var, _label, _module in _KEY_GATED_TOOLS:
    if os.environ.get(_env_var):
        app.include_router(_module.router, dependencies=[Depends(_require_api_key)])
    else:
        _app_log.warning(
            "Skill group %s disabled: %s is not set. Set this env var to enable it.",
            _label,
            _env_var,
        )


# --- MCP server --------------------------------------------------------------
# FastMCP mounts a Streamable-HTTP transport at /mcp/. Each @mcp.tool wraps the
# same async function that the REST router exposes, so we maintain one source
# of truth per capability.
mcp = FastMCP(name="copilot-mcp-soc-pack")

kev.register_mcp_tools(mcp)
epss.register_mcp_tools(mcp)
attack.register_mcp_tools(mcp)
crtsh.register_mcp_tools(mcp)
ransomwarelive.register_mcp_tools(mcp)
hibp.register_mcp_tools(mcp)
osv.register_mcp_tools(mcp)
circl_hashlookup.register_mcp_tools(mcp)
d3fend.register_mcp_tools(mcp)

for _env_var, _label, _module in _KEY_GATED_TOOLS:
    if os.environ.get(_env_var):
        _module.register_mcp_tools(mcp)

app.mount("/mcp", mcp.http_app())
