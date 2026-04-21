# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install build deps first for better layer caching.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --upgrade pip && pip install ".[tracing]"

# Create non-root user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; \
import json; \
r=urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3); \
sys.exit(0 if json.load(r).get('status')=='ok' else 1)"

CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8080"]
