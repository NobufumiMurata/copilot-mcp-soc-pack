"""Tests for the optional Application Insights tracing setup."""

from __future__ import annotations

from fastapi import FastAPI

from src.common import tracing


def test_configure_tracing_disabled_when_env_unset(monkeypatch, caplog):
    """No connection string -> no-op, returns False."""
    monkeypatch.delenv(tracing.APP_INSIGHTS_CONN_STR_ENV, raising=False)
    app = FastAPI()
    with caplog.at_level("INFO", logger=tracing.__name__):
        result = tracing.configure_tracing(app)
    assert result is False
    assert any(
        "tracing disabled" in record.message.lower() for record in caplog.records
    ), caplog.text


def test_configure_tracing_returns_false_when_dependency_missing(monkeypatch, caplog):
    """Connection string set but the optional package missing -> warn & False."""
    monkeypatch.setenv(
        tracing.APP_INSIGHTS_CONN_STR_ENV,
        "InstrumentationKey=00000000-0000-0000-0000-000000000000",
    )
    # Force the import path to fail by sabotaging the relevant module
    # in sys.modules. We restore via monkeypatch.
    import sys

    monkeypatch.setitem(sys.modules, "azure.monitor.opentelemetry", None)
    app = FastAPI()
    with caplog.at_level("WARNING", logger=tracing.__name__):
        result = tracing.configure_tracing(app)
    assert result is False
