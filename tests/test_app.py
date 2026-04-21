import httpx
from fastapi.testclient import TestClient

from src.app import app
from src.common import http as http_module


def test_health():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_ready_ok_when_upstream_returns_2xx():
    http_module._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": []}))
    )
    try:
        with TestClient(app) as client:
            response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"
    finally:
        http_module._client = None


def test_ready_503_when_upstream_5xx():
    http_module._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(503))
    )
    try:
        with TestClient(app) as client:
            response = client.get("/ready")
        assert response.status_code == 503
    finally:
        http_module._client = None


def test_ready_503_when_transport_error():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic", request=request)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    try:
        with TestClient(app) as client:
            response = client.get("/ready")
        assert response.status_code == 503
        assert "readiness probe failed" in response.json()["detail"]
    finally:
        http_module._client = None



def test_openapi_schema_contains_tools():
    client = TestClient(app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    paths = schema["paths"]
    assert "/kev/lookup" in paths
    assert "/kev/search" in paths
    assert "/epss/score" in paths
    assert "/attack/technique" in paths
    assert "/attack/search" in paths
    assert "/abusech/malwarebazaar/lookup" in paths
    assert "/abusech/malwarebazaar/recent" in paths
    assert "/abusech/threatfox/recent" in paths
    assert "/abusech/threatfox/search" in paths
    assert "/abusech/urlhaus/url" in paths
    assert "/abusech/urlhaus/host" in paths
    assert "/greynoise/classify" in paths
    assert "/abuseipdb/check" in paths
    assert "/crtsh/subdomains" in paths
    assert "/ransomware/recent" in paths
    assert "/ransomware/by_group" in paths
    assert "/ransomware/by_country" in paths
    assert "/ransomware/groups" in paths
    assert "/otx/ipv4" in paths
    assert "/otx/ipv6" in paths
    assert "/otx/domain" in paths
    assert "/otx/file" in paths
    assert "/otx/url" in paths
    assert "/hibp/breaches_by_domain" in paths
    assert "/hibp/breach" in paths
    assert "/osv/query_package" in paths
    assert "/osv/query_commit" in paths
    assert "/osv/vuln/{vuln_id}" in paths
    assert "/circl/hashlookup/md5/{hash_value}" in paths
    assert "/circl/hashlookup/sha1/{hash_value}" in paths
    assert "/circl/hashlookup/sha256/{hash_value}" in paths
    assert "/d3fend/defenses_for_attack/{attack_technique_id}" in paths
    assert "/d3fend/attacks_for_defense/{defense_label}" in paths


def test_openapi_operation_ids_are_clean():
    """Every advertised path/method must use an MCP-compatible operationId.

    Security Copilot agent manifests reference API skills by operationId
    in their AGENT ChildSkills list, so values must match the MCP tool
    names exactly (e.g. ``kev_lookup``, not the FastAPI default
    ``kev_lookup_endpoint_kev_lookup_get``).
    """
    client = TestClient(app)
    schema = client.get("/openapi.json").json()
    expected = {
        "kev_lookup",
        "kev_search",
        "epss_score",
        "attack_technique",
        "attack_search",
        "crtsh_subdomains",
        "ransomware_live_recent",
        "ransomware_live_by_group",
        "ransomware_live_by_country",
        "ransomware_live_groups",
        "hibp_breaches_by_domain",
        "hibp_breach",
        "osv_query_package",
        "osv_query_commit",
        "osv_get_vuln",
        "circl_hashlookup_md5",
        "circl_hashlookup_sha1",
        "circl_hashlookup_sha256",
        "d3fend_defenses_for_attack",
        "d3fend_attacks_for_defense",
    }
    actual = {
        op["operationId"]
        for path, methods in schema["paths"].items()
        for method, op in methods.items()
        if isinstance(op, dict) and "operationId" in op
    }
    missing = expected - actual
    assert not missing, f"missing clean operationIds: {sorted(missing)}"
    # Reject the FastAPI default mangling pattern entirely.
    bad = [op for op in actual if op.endswith("_get") or "_endpoint_" in op]
    assert not bad, f"unclean operationIds present: {sorted(bad)}"


def test_openapi_is_3_0_1_for_security_copilot():
    """Security Copilot only accepts OpenAPI 3.0 / 3.0.1 specs."""
    client = TestClient(app)
    schema = client.get("/openapi.json").json()
    assert schema["openapi"] == "3.0.1"

    # Optional fields must use the 3.0 nullable convention, not the 3.1
    # anyOf[..., {type: null}] pattern.
    kev_entry = schema["components"]["schemas"]["KevEntry"]["properties"]
    vendor = kev_entry["vendorProject"]
    assert vendor.get("nullable") is True
    assert vendor.get("type") == "string"
    assert "anyOf" not in vendor


def test_key_gated_tools_hidden_when_env_unset(monkeypatch):
    """Tools that require an upstream key are excluded from OpenAPI when
    the env var is missing. This protects SC's planner: an advertised but
    permanently-503 skill causes the whole multi-skill prompt to fail.
    """
    import importlib

    for env in (
        "GREYNOISE_API_KEY",
        "ABUSEIPDB_API_KEY",
        "ABUSE_CH_AUTH_KEY",
        "OTX_API_KEY",
    ):
        monkeypatch.delenv(env, raising=False)

    import src.app as app_module

    importlib.reload(app_module)
    try:
        schema = TestClient(app_module.app).get("/openapi.json").json()
        paths = schema["paths"]
        # Always-on tools are still there.
        assert "/kev/lookup" in paths
        assert "/d3fend/defenses_for_attack/{attack_technique_id}" in paths
        # Key-gated tools are absent.
        assert "/greynoise/classify" not in paths
        assert "/abuseipdb/check" not in paths
        assert "/abusech/threatfox/recent" not in paths
        assert "/otx/ipv4" not in paths
    finally:
        # Restore env vars and reload so subsequent tests see the full surface.
        for env in (
            "GREYNOISE_API_KEY",
            "ABUSEIPDB_API_KEY",
            "ABUSE_CH_AUTH_KEY",
            "OTX_API_KEY",
        ):
            monkeypatch.setenv(env, "test-fixture-key")
        importlib.reload(app_module)


def test_openapi_has_bearer_security_scheme():
    client = TestClient(app)
    schema = client.get("/openapi.json").json()
    schemes = schema["components"]["securitySchemes"]
    assert schemes["BearerAuth"]["type"] == "http"
    assert schemes["BearerAuth"]["scheme"] == "bearer"
    # ApiKeyAuth must be advertised first so Microsoft Security Copilot's
    # MS-schema agent manifest (Authorization Type: APIKey) can resolve
    # the API SkillGroup import. BearerAuth is kept as a fallback for the
    # legacy Custom plugin upload path.
    assert schemes["ApiKeyAuth"]["type"] == "apiKey"
    assert schemes["ApiKeyAuth"]["in"] == "header"
    assert schemes["ApiKeyAuth"]["name"] == "X-API-Key"
    assert schema["security"] == [{"ApiKeyAuth": []}, {"BearerAuth": []}]
