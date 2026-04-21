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
from fastapi.routing import APIRoute
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


# --- OpenAPI operationId clean-up --------------------------------------------
# FastAPI's default operationId mangler produces ugly identifiers such as
# ``kev_lookup_endpoint_kev_lookup_get`` which cannot be referenced from a
# Microsoft Security Copilot agent manifest's ``ChildSkills`` list.
# We expose every endpoint under the same name as the corresponding MCP
# tool (``kev_lookup``, ``epss_score``, ...) so that the OpenAPI plugin
# and the MCP server present a single, coherent skill catalogue.
#
# Some endpoint function names use shortened slugs (``mb_lookup_endpoint``,
# ``tf_search_endpoint``, ``otx_ipv4_endpoint``, ...) that do not match
# the public skill name; the explicit override map below resolves those
# cases. For every other endpoint we strip the ``_endpoint`` suffix and
# use the function name verbatim.
_OPERATION_ID_OVERRIDES: dict[str, str] = {
    # abuse.ch (abusech.py)
    "mb_lookup_endpoint": "malwarebazaar_lookup",
    "mb_recent_endpoint": "malwarebazaar_recent",
    "tf_recent_endpoint": "threatfox_recent",
    "tf_search_endpoint": "threatfox_search",
    "uh_url_endpoint": "urlhaus_lookup_url",
    "uh_host_endpoint": "urlhaus_lookup_host",
    # CIRCL hashlookup (circl_hashlookup.py)
    "circl_md5_endpoint": "circl_hashlookup_md5",
    "circl_sha1_endpoint": "circl_hashlookup_sha1",
    "circl_sha256_endpoint": "circl_hashlookup_sha256",
    # ransomware.live (ransomwarelive.py)
    "ransomware_recent_endpoint": "ransomware_live_recent",
    "ransomware_by_group_endpoint": "ransomware_live_by_group",
    "ransomware_by_country_endpoint": "ransomware_live_by_country",
    "ransomware_groups_endpoint": "ransomware_live_groups",
    # AlienVault OTX (otx.py)
    "otx_ipv4_endpoint": "otx_lookup_ipv4",
    "otx_ipv6_endpoint": "otx_lookup_ipv6",
    "otx_domain_endpoint": "otx_lookup_domain",
    "otx_file_endpoint": "otx_lookup_file",
    "otx_url_endpoint": "otx_lookup_url",
}


def _clean_operation_id(route: APIRoute) -> str:
    """Generate a clean, MCP-compatible operationId for an OpenAPI route.

    Used as ``FastAPI(generate_unique_id_function=...)``. Falls back to
    the route name (FastAPI's default basis) when no override is set.
    """
    name = route.name
    if name in _OPERATION_ID_OVERRIDES:
        return _OPERATION_ID_OVERRIDES[name]
    if name.endswith("_endpoint"):
        return name[: -len("_endpoint")]
    return name


app = FastAPI(
    title="Copilot MCP SOC Pack",
    version=__version__,
    description=(
        "Community SOC Pack for Microsoft Security Copilot. Bundles free security APIs "
        "(CISA KEV, FIRST EPSS, MITRE ATT&CK, Abuse.ch, GreyNoise, AbuseIPDB, crt.sh, "
        "ransomware.live) behind a single OpenAPI + MCP surface."
    ),
    lifespan=_lifespan,
    generate_unique_id_function=_clean_operation_id,
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
            # ApiKeyAuth listed first because Microsoft Security Copilot's
            # MS-schema agent manifest (Descriptor.Authorization Type:
            # APIKey, Key: X-API-Key, Location: Header) requires a matching
            # `apiKey` securityScheme in the OpenAPI spec for the API
            # SkillGroup import step to succeed. Without it the import
            # silently fails ("Failed to import OpenAPI spec") and any
            # AGENT skills referencing the resulting tools fail to publish
            # with "Invalid references: ...".
            "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            # BearerAuth retained for the older Custom plugin upload path
            # and any non-SC clients that prefer Authorization: Bearer.
            "BearerAuth": {"type": "http", "scheme": "bearer"},
        }
        schema["security"] = [{"ApiKeyAuth": []}, {"BearerAuth": []}]
    # Security Copilot's Agent Builder API Tool importer requires a
    # `servers[]` block in the OpenAPI spec to resolve the base URL of
    # each operation. The legacy Custom plugin upload path tolerated a
    # missing `servers` because the manifest carried `EndpointUrl`, but
    # the new UI does not consult the manifest's EndpointUrl during
    # import and surfaces "Failed to import OpenAPI spec" instead.
    # Operators self-hosting on a different FQDN can override this via
    # the MCP_SOC_PACK_PUBLIC_BASE_URL env var.
    public_base_url = os.environ.get("MCP_SOC_PACK_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if public_base_url and "servers" not in schema:
        schema["servers"] = [{"url": public_base_url}]
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
