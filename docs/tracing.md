# Application Insights tracing

The SOC Pack ships an **opt-in** [Azure Monitor OpenTelemetry](https://learn.microsoft.com/azure/azure-monitor/app/opentelemetry-enable?tabs=python) integration that emits FastAPI HTTP server spans, outbound `httpx` client spans, and structured logs to Application Insights. It is **disabled by default** — leaving the connection string unset keeps the stack fully offline.

## What gets instrumented

`src/common/tracing.py` calls `azure.monitor.opentelemetry.configure_azure_monitor()` plus `FastAPIInstrumentor.instrument_app()`. With those two switches you get:

- One server span per inbound HTTP request to any FastAPI route (including `/openapi.json` and the `/mcp/` SSE endpoint).
- One client span per outbound call made through the shared `httpx.AsyncClient` in `src/common/http.py` (so every upstream call to KEV, EPSS, abuse.ch, OTX, OSV, ransomware.live, etc. is traced).
- Standard `logging` records emitted by the app are forwarded as Application Insights traces.

The `service.name` resource attribute defaults to `copilot-mcp-soc-pack` and can be overridden with `OTEL_SERVICE_NAME`.

## Enabling tracing

### 1. Bicep (recommended)

`deploy/main.bicep` now supports a `enableAppInsights` parameter. When set to `true` it provisions a workspace-based Application Insights resource backed by the same Log Analytics workspace, then injects `APPLICATIONINSIGHTS_CONNECTION_STRING` and `OTEL_SERVICE_NAME` into the Container App as a secret-backed env var pair.

```bash
az deployment group create \
  --resource-group rg-copilot-mcp-soc-pack \
  --template-file deploy/main.bicep \
  --parameters apiKey=$(openssl rand -hex 32) \
               enableAppInsights=true
```

### 2. Bring-your-own connection string

If you already have an Application Insights resource (or are running outside Bicep), set the env var directly on the Container App / your local shell:

```bash
export APPLICATIONINSIGHTS_CONNECTION_STRING="InstrumentationKey=...;IngestionEndpoint=https://..."
export OTEL_SERVICE_NAME="copilot-mcp-soc-pack-prod"
uvicorn src.app:app --host 0.0.0.0 --port 8080
```

The published Docker image (`ghcr.io/nobufumimurata/copilot-mcp-soc-pack:latest`) is already built with the `[tracing]` extra, so no extra install steps are needed in the cloud. For local installs from source, use `pip install ".[tracing]"`.

## Verifying it works

After enabling tracing and triggering a couple of requests (`scripts/smoke.ps1` or any tool call), open the App Insights resource in the Azure portal and check:

- **Application map**: `copilot-mcp-soc-pack` should appear with downstream nodes for each upstream API hostname (e.g. `api.first.org`, `urlhaus-api.abuse.ch`).
- **Transaction search → Dependencies**: filter by `target` to see per-upstream latency and HTTP status counts.
- **Failures**: any 4xx/5xx surfaced by `request_with_retry` will show up here with the retry count visible in the span attributes.

A useful KQL starter query (in the App Insights Logs blade):

```kusto
dependencies
| where cloud_RoleName == "copilot-mcp-soc-pack"
| summarize count(), avg(duration), percentiles(duration, 50, 95) by target, resultCode
| order by count_ desc
```

## Disabling

Unset `APPLICATIONINSIGHTS_CONNECTION_STRING` (or set it to an empty string) and restart the app. `configure_tracing()` will log `Application Insights tracing disabled: APPLICATIONINSIGHTS_CONNECTION_STRING is not set.` at startup and skip all OpenTelemetry initialisation.

If you want to drop the dependency entirely, install without the extra (`pip install .` instead of `pip install ".[tracing]"`). The lazy import in `src/common/tracing.py` will detect the missing module and log a warning, but the app still starts normally.
