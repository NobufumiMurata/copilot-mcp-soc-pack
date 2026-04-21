"""Live evaluation harness for the SOC Pack tools.

These tests are **not** part of the default unit-test suite. They are
opt-in and require a deployed (or locally-running) SOC Pack instance.

Configuration (environment variables):
    EVAL_TARGET_URL        Base URL, e.g. https://soc-pack.example.com
                           or http://localhost:8080
    EVAL_API_KEY           Value of the X-API-Key header. Required if
                           the target enforces auth.
    EVAL_TIMEOUT_SECONDS   Per-request timeout (default: 20).

Run:
    # Requires the deployed Container App to be reachable.
    $env:EVAL_TARGET_URL = "https://copilot-mcp-soc-pack.<env>.<region>.azurecontainerapps.io"
    $env:EVAL_API_KEY = "<value>"
    pytest tests/eval -m eval -v

What this tests:
    Each scenario is a contract-style assertion against a single tool
    endpoint. We assert HTTP 200 + the **shape** of the response (top-
    level keys / types) rather than exact values, because upstream
    threat intel data changes every day.

    Scenarios for tools whose API key is not configured upstream are
    automatically marked SKIP by the dispatcher (the endpoint returns
    503 with a structured "missing key" payload — see src/app.py).
"""
