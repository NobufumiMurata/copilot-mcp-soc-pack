"""Optional Application Insights / OpenTelemetry tracing setup.

Activates only when ``APPLICATIONINSIGHTS_CONNECTION_STRING`` is set
**and** the ``azure-monitor-opentelemetry`` package is importable. Both
conditions failing is a no-op (logged at INFO so the dev workflow stays
silent).

This is intentionally opt-in: most deployments do not want to ship
telemetry to a third-party endpoint by default, and the dependency
itself adds a non-trivial install footprint.

When active, ``configure_azure_monitor()`` auto-instruments:
- FastAPI (HTTP server spans + status codes)
- httpx (outbound calls to upstream APIs as dependency spans)
- logging (correlated with traces)

so every request is searchable in App Insights with the upstream call
chain attached.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

APP_INSIGHTS_CONN_STR_ENV = "APPLICATIONINSIGHTS_CONNECTION_STRING"
SERVICE_NAME_ENV = "OTEL_SERVICE_NAME"
DEFAULT_SERVICE_NAME = "copilot-mcp-soc-pack"

_log = logging.getLogger(__name__)


def configure_tracing(app: FastAPI) -> bool:
    """Attempt to enable Azure Monitor tracing for the FastAPI app.

    Returns ``True`` when tracing was activated, ``False`` otherwise
    (missing env var, missing package, or initialisation failure).
    """
    conn_str = os.environ.get(APP_INSIGHTS_CONN_STR_ENV, "").strip()
    if not conn_str:
        _log.info(
            "Application Insights tracing disabled: %s is not set.",
            APP_INSIGHTS_CONN_STR_ENV,
        )
        return False

    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        _log.warning(
            "Application Insights tracing requested via %s but the "
            "`azure-monitor-opentelemetry` package is not installed. "
            "Add it to the deployment image (`pip install "
            "azure-monitor-opentelemetry`) to enable tracing.",
            APP_INSIGHTS_CONN_STR_ENV,
        )
        return False

    service_name = os.environ.get(SERVICE_NAME_ENV, "").strip() or DEFAULT_SERVICE_NAME
    # configure_azure_monitor reads APPLICATIONINSIGHTS_CONNECTION_STRING
    # from the environment automatically; we still pass it explicitly so
    # the call site is self-documenting.
    try:
        configure_azure_monitor(
            connection_string=conn_str,
            resource_attributes={"service.name": service_name},
        )
        FastAPIInstrumentor.instrument_app(app)
    except Exception as exc:  # pragma: no cover - defensive: never crash the app
        _log.error(
            "Failed to initialise Application Insights tracing: %s. "
            "Continuing without tracing.",
            exc,
        )
        return False

    _log.info(
        "Application Insights tracing enabled (service.name=%s).",
        service_name,
    )
    return True
