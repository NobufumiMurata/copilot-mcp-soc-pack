"""Per-tool unit tests.

Each test calls the underlying ``async`` helper (the single source of truth
that both the REST router and the MCP wrapper delegate to) directly via
``asyncio.run``. The shared ``httpx.AsyncClient`` is swapped for a
``MockTransport``-backed client by the ``mock_http`` fixture in
``conftest.py``, so every assertion is hermetic and there is no outbound
traffic during the test run.

The goal is to lock in:

- happy-path response parsing for every tool;
- correct mapping of upstream error codes (401 / 404 / 429 / 5xx) to
  ``HTTPException`` status codes; and
- the "missing upstream API key -> 503" branch for every tool that
  requires one.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from fastapi import HTTPException

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


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# --- KEV --------------------------------------------------------------------


_KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-3400",
            "vendorProject": "Palo Alto Networks",
            "product": "PAN-OS",
            "vulnerabilityName": "PAN-OS Command Injection",
            "dateAdded": "2024-04-12",
            "shortDescription": "...",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2023-23397",
            "vendorProject": "Microsoft",
            "product": "Outlook",
            "vulnerabilityName": "Microsoft Outlook Privilege Escalation",
            "dateAdded": "2023-03-14",
            "knownRansomwareCampaignUse": "Known",
        },
    ]
}


def test_kev_lookup_hit(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "www.cisa.gov"
        return httpx.Response(200, json=_KEV_PAYLOAD)

    mock_http(handler)
    entry = _run(kev._kev_lookup("cve-2024-3400"))
    assert entry is not None
    assert entry.cveID == "CVE-2024-3400"
    assert entry.vendorProject == "Palo Alto Networks"


def test_kev_lookup_miss(mock_http):
    mock_http(lambda r: httpx.Response(200, json=_KEV_PAYLOAD))
    assert _run(kev._kev_lookup("CVE-9999-0000")) is None


def test_kev_search_ransomware_only_filters(mock_http):
    mock_http(lambda r: httpx.Response(200, json=_KEV_PAYLOAD))
    results = _run(kev._kev_search(ransomware_only=True))
    assert [e.cveID for e in results] == ["CVE-2023-23397"]


def test_kev_search_vendor_substring(mock_http):
    mock_http(lambda r: httpx.Response(200, json=_KEV_PAYLOAD))
    results = _run(kev._kev_search(vendor="microsoft"))
    assert len(results) == 1
    assert results[0].vendorProject == "Microsoft"


def test_kev_catalog_fetch_retries_5xx():
    """KEV catalog fetch should ride out a single CISA edge cache 503."""
    from src.common import http as http_module

    responses = [httpx.Response(503), httpx.Response(200, json=_KEV_PAYLOAD)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=_KEV_PAYLOAD)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    # Tighten retry timing so the test doesn't sleep for jitter.
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        entry = _run(kev._kev_lookup("CVE-2024-3400"))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert entry is not None
    assert seen["n"] == 2  # 1 failure + 1 success


# --- EPSS -------------------------------------------------------------------


def test_epss_score_parses_floats(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.first.org"
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2024-3400",
                        "epss": "0.97123",
                        "percentile": "0.99",
                        "date": "2026-04-19",
                    }
                ]
            },
        )

    mock_http(handler)
    scores = _run(epss._epss_score(["CVE-2024-3400"]))
    assert len(scores) == 1
    assert scores[0].cve == "CVE-2024-3400"
    assert scores[0].epss == pytest.approx(0.97123)
    assert scores[0].percentile == pytest.approx(0.99)


def test_epss_score_empty_input_skips_http(mock_http):
    called = False

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        nonlocal called
        called = True
        return httpx.Response(500)

    mock_http(handler)
    assert _run(epss._epss_score([])) == []
    assert called is False


def test_epss_score_retries_5xx():
    """EPSS score lookup should ride out a transient FIRST 502."""
    from src.common import http as http_module

    payload = {
        "data": [
            {
                "cve": "CVE-2024-3400",
                "epss": "0.5",
                "percentile": "0.9",
                "date": "2026-04-19",
            }
        ]
    }
    responses = [httpx.Response(502), httpx.Response(200, json=payload)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=payload)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        scores = _run(epss._epss_score(["CVE-2024-3400"]))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert len(scores) == 1
    assert seen["n"] == 2


# --- AbuseIPDB --------------------------------------------------------------


def test_abuseipdb_no_key_returns_503(monkeypatch):
    monkeypatch.delenv(abuseipdb.ABUSEIPDB_API_KEY_ENV, raising=False)
    with pytest.raises(HTTPException) as exc:
        _run(abuseipdb._check("1.2.3.4", 90))
    assert exc.value.status_code == 503
    assert "ABUSEIPDB_API_KEY" in exc.value.detail


def test_abuseipdb_check_ok(mock_http, monkeypatch):
    monkeypatch.setenv(abuseipdb.ABUSEIPDB_API_KEY_ENV, "fake-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Key") == "fake-key"
        assert request.url.params["ipAddress"] == "1.2.3.4"
        return httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 87,
                    "countryCode": "US",
                    "isp": "Example",
                    "totalReports": 12,
                    "isPublic": True,
                }
            },
        )

    mock_http(handler)
    result = _run(abuseipdb._check("1.2.3.4", 90))
    assert result.abuseConfidenceScore == 87
    assert result.countryCode == "US"


def test_abuseipdb_unauthorized(mock_http, monkeypatch):
    monkeypatch.setenv(abuseipdb.ABUSEIPDB_API_KEY_ENV, "bad-key")
    mock_http(lambda r: httpx.Response(401))
    with pytest.raises(HTTPException) as exc:
        _run(abuseipdb._check("1.2.3.4", 90))
    assert exc.value.status_code == 401


def test_abuseipdb_rate_limited(mock_http, monkeypatch):
    monkeypatch.setenv(abuseipdb.ABUSEIPDB_API_KEY_ENV, "k")
    mock_http(lambda r: httpx.Response(429))
    with pytest.raises(HTTPException) as exc:
        _run(abuseipdb._check("1.2.3.4", 90))
    assert exc.value.status_code == 429


def test_abuseipdb_retries_5xx(monkeypatch):
    """AbuseIPDB check should ride out a single transient 503."""
    from src.common import http as http_module

    monkeypatch.setenv(abuseipdb.ABUSEIPDB_API_KEY_ENV, "k")
    payload = {"data": {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 10}}
    responses = [httpx.Response(503), httpx.Response(200, json=payload)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=payload)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        result = _run(abuseipdb._check("1.2.3.4", 90))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert result.abuseConfidenceScore == 10
    assert seen["n"] == 2


# --- GreyNoise -------------------------------------------------------------


def test_greynoise_no_key_returns_503(monkeypatch):
    monkeypatch.delenv(greynoise.GREYNOISE_API_KEY_ENV, raising=False)
    with pytest.raises(HTTPException) as exc:
        _run(greynoise._classify("8.8.8.8"))
    assert exc.value.status_code == 503


def test_greynoise_ok(mock_http, monkeypatch):
    monkeypatch.setenv(greynoise.GREYNOISE_API_KEY_ENV, "k")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("key") == "k"
        return httpx.Response(
            200,
            json={
                "ip": "8.8.8.8",
                "noise": False,
                "riot": True,
                "classification": "benign",
                "name": "Google Public DNS",
            },
        )

    mock_http(handler)
    result = _run(greynoise._classify("8.8.8.8"))
    assert result.riot is True
    assert result.name == "Google Public DNS"


def test_greynoise_404_treated_as_miss(mock_http, monkeypatch):
    monkeypatch.setenv(greynoise.GREYNOISE_API_KEY_ENV, "k")
    mock_http(
        lambda r: httpx.Response(
            404, json={"ip": "192.0.2.1", "message": "IP not observed scanning the internet"}
        )
    )
    result = _run(greynoise._classify("192.0.2.1"))
    assert result.message and "not observed" in result.message


def test_greynoise_unauthorized(mock_http, monkeypatch):
    monkeypatch.setenv(greynoise.GREYNOISE_API_KEY_ENV, "bad")
    mock_http(lambda r: httpx.Response(401))
    with pytest.raises(HTTPException) as exc:
        _run(greynoise._classify("1.1.1.1"))
    assert exc.value.status_code == 401


def test_greynoise_retries_5xx(monkeypatch):
    """GreyNoise classify should ride out a single transient 502."""
    from src.common import http as http_module

    monkeypatch.setenv(greynoise.GREYNOISE_API_KEY_ENV, "k")
    payload = {"ip": "8.8.8.8", "noise": False, "riot": True, "classification": "benign"}
    responses = [httpx.Response(502), httpx.Response(200, json=payload)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=payload)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        result = _run(greynoise._classify("8.8.8.8"))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert result.classification == "benign"
    assert seen["n"] == 2


# --- Abuse.ch --------------------------------------------------------------


def test_abusech_no_key_returns_503(monkeypatch):
    monkeypatch.delenv(abusech.ABUSE_CH_AUTH_KEY_ENV, raising=False)
    with pytest.raises(HTTPException) as exc:
        _run(abusech._mb_lookup("deadbeef"))
    assert exc.value.status_code == 503


def test_abusech_unauthorized(mock_http, monkeypatch):
    monkeypatch.setenv(abusech.ABUSE_CH_AUTH_KEY_ENV, "bad")
    mock_http(lambda r: httpx.Response(401))
    with pytest.raises(HTTPException) as exc:
        _run(abusech._mb_lookup("deadbeef"))
    assert exc.value.status_code == 401


def test_abusech_malwarebazaar_lookup_ok(mock_http, monkeypatch):
    monkeypatch.setenv(abusech.ABUSE_CH_AUTH_KEY_ENV, "k")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Auth-Key") == "k"
        assert request.url.host == "mb-api.abuse.ch"
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "a" * 64,
                        "file_name": "evil.exe",
                        "file_size": 12345,
                        "signature": "Emotet",
                        "tags": ["emotet", "exe"],
                    }
                ],
            },
        )

    mock_http(handler)
    samples = _run(abusech._mb_lookup("a" * 64))
    assert len(samples) == 1
    assert samples[0].signature == "Emotet"
    assert samples[0].tags == ["emotet", "exe"]


# --- crt.sh -----------------------------------------------------------------


def test_crtsh_subdomains_ok(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "crt.sh"
        return httpx.Response(
            200,
            json=[
                {"name_value": "www.example.com\nmail.example.com"},
                {"name_value": "*.example.com"},
                {"name_value": "user@example.com"},
                {"name_value": "api.example.com"},
            ],
        )

    mock_http(handler)
    result = _run(crtsh._subdomains("example.com"))
    assert set(result.subdomains) == {"www.example.com", "mail.example.com", "api.example.com"}
    assert result.truncated is False
    assert result.count == 3


def test_crtsh_404_returns_empty(mock_http):
    mock_http(lambda r: httpx.Response(404))
    result = _run(crtsh._subdomains("nonexistent.example"))
    assert result.subdomains == []
    assert result.count == 0


def test_crtsh_500_returns_503(mock_http):
    mock_http(lambda r: httpx.Response(502))
    with pytest.raises(HTTPException) as exc:
        _run(crtsh._subdomains("example.com"))
    assert exc.value.status_code == 503


# --- HIBP -------------------------------------------------------------------


def test_hibp_breaches_for_domain_ok(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "haveibeenpwned.com"
        assert request.url.params["domain"] == "adobe.com"
        return httpx.Response(
            200,
            json=[
                {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "Domain": "adobe.com",
                    "BreachDate": "2013-10-04",
                    "PwnCount": 152445165,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsVerified": True,
                }
            ],
        )

    mock_http(handler)
    breaches = _run(hibp._breaches_for_domain("adobe.com"))
    assert len(breaches) == 1
    assert breaches[0].Name == "Adobe"
    assert "Email addresses" in breaches[0].DataClasses


def test_hibp_breach_by_name_404_returns_none(mock_http):
    mock_http(lambda r: httpx.Response(404))
    assert _run(hibp._breach_by_name("DoesNotExist")) is None


def test_hibp_rate_limited(mock_http):
    mock_http(lambda r: httpx.Response(429))
    with pytest.raises(HTTPException) as exc:
        _run(hibp._breaches_for_domain("example.com"))
    assert exc.value.status_code == 429


def test_hibp_breaches_retries_5xx():
    """HIBP /breaches should ride out a single transient 503."""
    from src.common import http as http_module

    payload = [
        {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com", "PwnCount": 153_000_000}
    ]
    responses = [httpx.Response(503), httpx.Response(200, json=payload)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=payload)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        breaches = _run(hibp._breaches_for_domain("adobe.com"))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert len(breaches) == 1
    assert breaches[0].Name == "Adobe"
    assert seen["n"] == 2


# --- OTX --------------------------------------------------------------------


def test_otx_no_key_returns_503(monkeypatch):
    monkeypatch.delenv(otx.OTX_API_KEY_ENV, raising=False)
    with pytest.raises(HTTPException) as exc:
        _run(otx._otx_get("IPv4", "8.8.8.8"))
    assert exc.value.status_code == 503


def test_otx_indicator_ok(mock_http, monkeypatch):
    monkeypatch.setenv(otx.OTX_API_KEY_ENV, "k")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-OTX-API-KEY") == "k"
        return httpx.Response(
            200,
            json={
                "indicator": "8.8.8.8",
                "type": "IPv4",
                "type_title": "IPv4",
                "reputation": 0,
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {
                            "id": "p1",
                            "name": "Pulse 1",
                            "tags": ["scanner"],
                            "malware_families": [{"display_name": "FamilyX"}],
                            "attack_ids": [{"id": "T1059"}],
                            "author": {"username": "alice"},
                        }
                    ],
                    "references": ["https://example.com/r1"],
                },
                "sections": ["general", "geo"],
            },
        )

    mock_http(handler)
    result = _run(otx._otx_get("IPv4", "8.8.8.8"))
    assert result.pulse_count == 2
    assert result.pulses[0].malware_families == ["FamilyX"]
    assert result.pulses[0].attack_ids == ["T1059"]
    assert result.references == ["https://example.com/r1"]


def test_otx_indicator_retries_5xx(monkeypatch):
    """OTX general fetch should ride out a single 502 from the API gateway."""
    from src.common import http as http_module

    monkeypatch.setenv(otx.OTX_API_KEY_ENV, "k")
    payload = {
        "indicator": "8.8.8.8",
        "type": "IPv4",
        "pulse_info": {"count": 0, "pulses": [], "references": []},
    }
    responses = [httpx.Response(502), httpx.Response(200, json=payload)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=payload)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        result = _run(otx._otx_get("IPv4", "8.8.8.8"))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert result.indicator == "8.8.8.8"
    assert seen["n"] == 2


# --- ransomware.live --------------------------------------------------------


def test_ransomwarelive_recent_ok(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.ransomware.live"
        return httpx.Response(
            200,
            json=[
                {
                    "victim": "Acme Corp",
                    "group": "lockbit3",
                    "discovered": "2026-04-19",
                    "country": "US",
                }
            ],
        )

    mock_http(handler)
    victims = _run(ransomwarelive._recent(limit=10))
    assert len(victims) == 1
    assert victims[0].victim == "Acme Corp"
    assert victims[0].group == "lockbit3"


# --- ATT&CK -----------------------------------------------------------------


_ATTACK_STIX = {
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Phishing",
            "description": "Adversaries may send phishing messages.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566", "url": "https://..."}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
            "x_mitre_platforms": ["Windows", "macOS"],
        }
    ]
}


def test_attack_technique_lookup_ok(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert "raw.githubusercontent.com" in request.url.host
        return httpx.Response(200, json=_ATTACK_STIX)

    mock_http(handler)
    technique = _run(attack._attack_technique("T1566"))
    assert technique is not None
    assert technique.name == "Phishing"
    assert "initial-access" in technique.tactics


def test_attack_search_substring(mock_http):
    mock_http(lambda r: httpx.Response(200, json=_ATTACK_STIX))
    results = _run(attack._attack_search("phish"))
    assert any(t.technique_id == "T1566" for t in results)


def test_attack_bundle_fetch_retries_5xx():
    """ATT&CK bundle fetch should ride out a single raw.githubusercontent 503."""
    from src.common import http as http_module

    responses = [httpx.Response(503), httpx.Response(200, json=_ATTACK_STIX)]
    seen = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["n"] += 1
        return responses.pop(0) if responses else httpx.Response(200, json=_ATTACK_STIX)

    http_module._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    import src.common.http as h

    original_base = h.DEFAULT_BACKOFF_BASE
    h.DEFAULT_BACKOFF_BASE = 0.0
    try:
        technique = _run(attack._attack_technique("T1566"))
    finally:
        h.DEFAULT_BACKOFF_BASE = original_base
    assert technique is not None
    assert seen["n"] == 2
