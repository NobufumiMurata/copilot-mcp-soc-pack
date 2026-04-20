"""copilot-mcp-soc-pack — entrypoint package."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("copilot-mcp-soc-pack")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0+local"

