"""Pytest fixtures for the live evaluation harness."""

from __future__ import annotations

import os

import httpx
import pytest

EVAL_TARGET_URL_ENV = "EVAL_TARGET_URL"
EVAL_API_KEY_ENV = "EVAL_API_KEY"
EVAL_TIMEOUT_ENV = "EVAL_TIMEOUT_SECONDS"


@pytest.fixture(scope="session")
def eval_target_url() -> str:
    raw = os.environ.get(EVAL_TARGET_URL_ENV, "").strip().rstrip("/")
    if not raw:
        pytest.skip(
            f"{EVAL_TARGET_URL_ENV} is not set; live evaluation harness skipped. "
            "Set EVAL_TARGET_URL=http://localhost:8080 (or the deployed URL) "
            "and EVAL_API_KEY to run.",
            allow_module_level=False,
        )
    return raw


@pytest.fixture(scope="session")
def eval_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    api_key = os.environ.get(EVAL_API_KEY_ENV, "").strip()
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


@pytest.fixture(scope="session")
def eval_timeout() -> float:
    raw = os.environ.get(EVAL_TIMEOUT_ENV, "20").strip()
    try:
        return float(raw)
    except ValueError:
        return 20.0


@pytest.fixture(scope="session")
def eval_client(eval_target_url: str, eval_headers: dict[str, str], eval_timeout: float):
    with httpx.Client(
        base_url=eval_target_url,
        headers=eval_headers,
        timeout=eval_timeout,
        follow_redirects=True,
    ) as client:
        yield client
