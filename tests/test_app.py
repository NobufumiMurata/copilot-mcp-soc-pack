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
