"""Scenario-driven live evaluation of every SOC Pack tool.

Each scenario is a ``Scenario`` describing one HTTP call and the
contract assertions that must hold for the response. Scenarios cover
every tool group exposed by the Container App so this harness doubles
as a deployment readiness check.

Tools that require an upstream API key (abuse.ch / GreyNoise /
AbuseIPDB / OTX) are scenario-tagged with ``requires_upstream_key``;
when their endpoint is missing from the deployment (because the env
var was not set) the dispatcher returns 404 and the scenario is
auto-skipped instead of failed. This matches the conditional-
registration behaviour documented in the README.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest


@dataclass(frozen=True)
class Scenario:
    """One contract-style live assertion against a SOC Pack endpoint."""

    name: str
    method: str
    path: str
    params: dict[str, Any] = field(default_factory=dict)
    json_body: dict[str, Any] | None = None
    expected_status: int = 200
    # Optional list of (name, callable) shape assertions on the JSON body.
    asserts: tuple[tuple[str, Callable[[Any], bool]], ...] = ()
    # Tools that require an upstream API key configured in the deployment.
    # When the route is absent (404), the scenario is skipped, not failed.
    requires_upstream_key: bool = False
    # Status codes that indicate "upstream had no data for this query"
    # rather than a real failure. The harness skips on these.
    upstream_no_data_status: tuple[int, ...] = ()


def _has_keys(*keys: str) -> Callable[[Any], bool]:
    def _check(payload: Any) -> bool:
        return isinstance(payload, dict) and all(k in payload for k in keys)

    return _check


def _is_list(min_len: int = 0) -> Callable[[Any], bool]:
    def _check(payload: Any) -> bool:
        return isinstance(payload, list) and len(payload) >= min_len

    return _check


def _is_dict_or_list() -> Callable[[Any], bool]:
    return lambda payload: isinstance(payload, dict | list)


# Stable, well-known fixtures. These are public reference values that have
# been around for years and are extremely unlikely to disappear.
SCENARIOS: tuple[Scenario, ...] = (
    # --- meta ---------------------------------------------------------
    Scenario(
        name="health",
        method="GET",
        path="/health",
        asserts=(
            ("body has status", _has_keys("status", "version")),
            ("status is ok", lambda b: b.get("status") == "ok"),
        ),
    ),
    Scenario(
        name="openapi_schema",
        method="GET",
        path="/openapi.json",
        asserts=(
            ("openapi version present", _has_keys("openapi", "paths")),
            ("openapi is 3.0.x", lambda b: str(b.get("openapi", "")).startswith("3.0")),
        ),
    ),
    # --- KEV ----------------------------------------------------------
    Scenario(
        name="kev_lookup_known_cve",
        method="GET",
        path="/kev/lookup",
        params={"cve_id": "CVE-2024-3400"},
        asserts=(
            ("cveID echoed", lambda b: b.get("cveID") == "CVE-2024-3400"),
            ("dateAdded present", _has_keys("dateAdded")),
        ),
    ),
    Scenario(
        name="kev_search_recent",
        method="GET",
        path="/kev/search",
        params={"vendor": "Microsoft", "limit": 5},
        asserts=(("returns a list", _is_list()),),
    ),
    # --- EPSS ---------------------------------------------------------
    Scenario(
        name="epss_score_known_cve",
        method="GET",
        path="/epss/score",
        params={"cve": "CVE-2024-3400"},
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    # --- ATT&CK -------------------------------------------------------
    Scenario(
        name="attack_technique_powershell",
        method="GET",
        path="/attack/technique",
        params={"technique_id": "T1059.001"},
        asserts=(("name present", _has_keys("name")),),
    ),
    Scenario(
        name="attack_search_term",
        method="GET",
        path="/attack/search",
        params={"query": "PowerShell", "limit": 5},
        asserts=(("returns a list", _is_list()),),
    ),
    # --- crt.sh -------------------------------------------------------
    Scenario(
        name="crtsh_subdomains_example",
        method="GET",
        path="/crtsh/subdomains",
        params={"domain": "example.com"},
        # crt.sh is frequently slow / overloaded; treat 504 as a no-op.
        upstream_no_data_status=(504,),
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    # --- ransomware.live ---------------------------------------------
    Scenario(
        name="ransomware_recent",
        method="GET",
        path="/ransomware/recent",
        params={"limit": 5},
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    Scenario(
        name="ransomware_groups",
        method="GET",
        path="/ransomware/groups",
        params={"limit": 50},
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    # --- HIBP ---------------------------------------------------------
    Scenario(
        name="hibp_breach_known",
        method="GET",
        path="/hibp/breach",
        params={"name": "Adobe"},
        asserts=(
            ("name field echoed", lambda b: isinstance(b, dict) and b.get("Name") == "Adobe"),
        ),
    ),
    # --- OSV.dev ------------------------------------------------------
    Scenario(
        name="osv_query_known_vuln_pypi",
        method="GET",
        path="/osv/query_package",
        params={"name": "requests", "ecosystem": "PyPI", "version": "2.20.0"},
        asserts=(("response is dict", lambda b: isinstance(b, dict)),),
    ),
    Scenario(
        name="osv_get_known_vuln",
        method="GET",
        path="/osv/vuln/GHSA-x84v-xcm2-53pg",
        asserts=(("id echoed", lambda b: isinstance(b, dict) and b.get("id")),),
    ),
    # --- CIRCL hashlookup --------------------------------------------
    Scenario(
        name="circl_hashlookup_known_md5",
        method="GET",
        # MD5 of a NSRL-known whitelisted file (cmd.exe from Win10).
        path="/circl/hashlookup/md5/8ed4b4ed952526d89899e723f3488de4",
        asserts=(("response is dict", lambda b: isinstance(b, dict)),),
    ),
    # --- D3FEND -------------------------------------------------------
    Scenario(
        name="d3fend_defenses_for_attack",
        method="GET",
        path="/d3fend/defenses_for_attack/T1486",
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    # --- abuse.ch (gated) --------------------------------------------
    Scenario(
        name="threatfox_search_known_ip",
        method="GET",
        path="/abusech/threatfox/search",
        params={"ioc": "185.220.101.1"},
        requires_upstream_key=True,
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    Scenario(
        name="malwarebazaar_lookup_eicar",
        method="GET",
        path="/abusech/malwarebazaar/lookup",
        # SHA256 of EICAR test file. MalwareBazaar may or may not have it
        # depending on its current corpus; treat 502 (hash_not_found) as skip.
        params={"hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
        requires_upstream_key=True,
        upstream_no_data_status=(502,),
        asserts=(("response is dict", lambda b: isinstance(b, dict)),),
    ),
    Scenario(
        name="urlhaus_lookup_host",
        method="GET",
        path="/abusech/urlhaus/host",
        params={"host": "urlhaus.abuse.ch"},
        requires_upstream_key=True,
        asserts=(("response is dict or list", _is_dict_or_list()),),
    ),
    # --- AbuseIPDB (gated) -------------------------------------------
    Scenario(
        name="abuseipdb_check_tor_node",
        method="GET",
        path="/abuseipdb/check",
        params={"ip": "185.220.101.1"},
        requires_upstream_key=True,
        asserts=(("response is dict", lambda b: isinstance(b, dict)),),
    ),
    # --- OTX (gated) --------------------------------------------------
    Scenario(
        name="otx_lookup_ipv4_cloudflare",
        method="GET",
        path="/otx/ipv4",
        params={"ip": "1.1.1.1"},
        requires_upstream_key=True,
        asserts=(("response is dict", lambda b: isinstance(b, dict)),),
    ),
)


@pytest.mark.eval
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_scenario(scenario: Scenario, eval_client: httpx.Client) -> None:
    """Run one live scenario and assert the contract holds."""
    try:
        if scenario.method == "GET":
            response = eval_client.get(scenario.path, params=scenario.params)
        elif scenario.method == "POST":
            response = eval_client.post(
                scenario.path, params=scenario.params, json=scenario.json_body
            )
        else:
            pytest.fail(f"Unsupported method {scenario.method!r}")
    except httpx.TimeoutException as exc:
        # Upstream APIs (notably crt.sh) are intermittently slow. Surface
        # as skip so a transient slowdown doesn't fail the whole suite.
        pytest.skip(f"{scenario.path} timed out: {exc}")

    # Conditional-registration auto-skip: gated tools that aren't deployed
    # respond 404 from FastAPI's default router.
    if scenario.requires_upstream_key and response.status_code == 404:
        pytest.skip(
            f"{scenario.path} is not registered on the target — "
            "the corresponding upstream API key env var is unset."
        )

    # Surface upstream-key explicit-skip path: gated tools that ARE
    # registered but still return 503 with a missing-key payload.
    # Also catches generic 503s that report an upstream as unavailable
    # (e.g. crt.sh frequently returns "upstream is currently unavailable").
    if response.status_code == 503:
        try:
            detail = response.json().get("detail", "")
        except Exception:
            detail = response.text
        detail_lc = str(detail).lower()
        if any(token in detail_lc for token in ("missing", "api key", "unavailable", "retry")):
            pytest.skip(f"{scenario.path} returned 503 (upstream issue): {detail}")

    # Upstream "no data for this query" code (e.g. MalwareBazaar
    # hash_not_found) — skip rather than fail. This is per-scenario.
    if response.status_code in scenario.upstream_no_data_status:
        pytest.skip(
            f"{scenario.path} returned {response.status_code} "
            f"(upstream has no data for the test fixture, treated as no-op): "
            f"{response.text[:200]}"
        )

    assert response.status_code == scenario.expected_status, (
        f"{scenario.name}: expected {scenario.expected_status} got "
        f"{response.status_code}: {response.text[:300]}"
    )

    if scenario.asserts:
        try:
            payload = response.json()
        except ValueError as exc:
            pytest.fail(f"{scenario.name}: response is not JSON: {exc}")

        for label, check in scenario.asserts:
            assert check(payload), (
                f"{scenario.name}: contract assertion failed: {label}. "
                f"Payload: {str(payload)[:300]}"
            )
