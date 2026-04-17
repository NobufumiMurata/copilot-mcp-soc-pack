from fastapi.testclient import TestClient

from src.app import app


def test_health():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


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


def test_openapi_has_apikey_security_scheme():
    client = TestClient(app)
    schema = client.get("/openapi.json").json()
    schemes = schema["components"]["securitySchemes"]
    assert schemes["ApiKeyAuth"]["type"] == "apiKey"
    assert schemes["ApiKeyAuth"]["in"] == "header"
    assert schemes["ApiKeyAuth"]["name"] == "X-API-Key"
