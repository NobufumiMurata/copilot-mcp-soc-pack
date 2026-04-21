# Live evaluation harness

The SOC Pack ships a structured live evaluation harness under
[`tests/eval/`](../tests/eval). It is a contract-style suite that
hits every tool group on a deployed (or locally running) instance and
asserts the response **shape** is what Security Copilot / MCP clients
expect.

It complements the existing assets:

| Asset | Scope | When to run |
|------|------|------|
| `pytest tests/` | Unit tests against mocked upstreams. No network. | Every commit (CI). |
| `scripts/smoke.ps1` | 30-second curl-style sanity check, prints a pass/skip/fail table. | Right after `Deploy to Azure` or an image bump. |
| `scripts/eval.ps1` (this) | Full contract suite over every endpoint, real upstream calls. | Nightly, before promoting an image to production, or before tagging a release. |

## What it tests

Each scenario is a `Scenario` record in
[`tests/eval/test_live_scenarios.py`](../tests/eval/test_live_scenarios.py)
with:

- HTTP method + path + params (or JSON body for POST routes).
- Expected status code (defaults to 200).
- A list of contract assertions on the response body
  (e.g. `cveID` echoed, `vulns` key present, response is a non-empty list).

The harness deliberately does **not** assert exact values, because
upstream threat-intel data changes daily. It catches regressions in
schema/shape and in the conditional-registration plumbing.

### Auto-skip rules

Scenarios for tools whose upstream API key is not configured on the
target are auto-skipped, in two ways:

1. **Route absent (HTTP 404)** — when the env var is unset on the
   Container App, the route is never registered. The harness skips
   instead of failing.
2. **Route present, key still missing (HTTP 503)** — when the route is
   registered but the upstream rejects the request, the harness reads
   the `detail` and skips.

This matches the conditional-registration policy in
[`src/app.py`](../src/app.py) and lets the same eval suite run against
both minimum-viable deployments (KEV / EPSS / ATT&CK / crt.sh /
ransomware.live / OSV / CIRCL / D3FEND / HIBP only) and full
deployments (every upstream key configured).

## Configuration

Set the following environment variables before running:

| Variable | Required | Default | Notes |
|------|------|------|------|
| `EVAL_TARGET_URL` | ✅ | — | Base URL with scheme. Example: `https://copilot-mcp-soc-pack.<env>.<region>.azurecontainerapps.io`. |
| `EVAL_API_KEY` | conditional | — | `X-API-Key` value. Required if the target enforces auth. |
| `EVAL_TIMEOUT_SECONDS` | optional | `20` | Per-request timeout. |

If `EVAL_TARGET_URL` is unset, the entire harness module is skipped —
this keeps the default `pytest tests/` invocation fast and offline.

## Run it locally

```powershell
# Against the deployed Container App
$env:EVAL_API_KEY = az containerapp secret show -g <rg> -n <app> `
  --secret-name api-key --query value -o tsv

./scripts/eval.ps1 -Fqdn copilot-mcp-soc-pack.<env>.<region>.azurecontainerapps.io

# Against a local uvicorn
uvicorn src.app:app --port 8080 &
./scripts/eval.ps1 -Fqdn localhost:8080 -PytestArgs '-k', 'kev'
```

Or invoke pytest directly:

```powershell
$env:EVAL_TARGET_URL = "https://copilot-mcp-soc-pack.<env>.<region>.azurecontainerapps.io"
$env:EVAL_API_KEY = "<value>"
pytest tests/eval -m eval -v
```

## Run it in CI

The repository ships a `.github/workflows/eval.yml` workflow that you
can trigger manually (`workflow_dispatch`) and that also runs nightly.
It expects two repository secrets:

- `EVAL_TARGET_URL` — base URL of the long-running test deployment.
- `EVAL_API_KEY` — the `X-API-Key` value for that deployment.

Configure them under **Settings → Secrets and variables → Actions** in
your fork. Without those secrets the workflow gracefully no-ops.

## Adding a new scenario

1. Add a tool module under `src/tools/<name>.py` (see
   [tool-module instructions](../.github/instructions/tool-module.instructions.md)).
2. Append a `Scenario(...)` entry to `SCENARIOS` in
   [`tests/eval/test_live_scenarios.py`](../tests/eval/test_live_scenarios.py)
   that exercises a stable, public, long-lived input.
3. Set `requires_upstream_key=True` if the tool is gated.
4. Keep contract assertions to **shape only** (key presence, type,
   list-min-length). Never assert exact upstream values.
