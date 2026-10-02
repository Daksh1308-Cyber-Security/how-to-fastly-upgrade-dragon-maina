# Incident Response Automation — API + test image
#
# Single image for the API service and the test suite. Python 3.11 is
# pinned deliberately -- see docs/ARCHITECTURE.md section 9 for why the
# host's 3.14 is not used.
#
# This image contains the engine, the API and Volatility. It does NOT
# contain, and must never contain, tooling that can capture host memory
# or mutate real infrastructure (docs/SECURITY.md section 2).

FROM python:3.11-slim

# Prevent .pyc files and __pycache__ from bloating the image/layers.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Volatility symbol tables download on first Windows use and are slow.
# They cache under /root/.cache, which docker-compose mounts from
# data/vol-cache so they survive container restarts.
# NEVER run `docker compose down -v` -- it destroys this cache.
ENV XDG_CACHE_HOME=/root/.cache \
    VOLATILITY_CACHE_DIR=/root/.cache

# Dependencies first so application edits do not bust the layer cache.
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

# Application code.
COPY soar/ ./soar/
COPY playbooks/ ./playbooks/
COPY fixtures/ ./fixtures/
COPY scripts/ ./scripts/
COPY tests/ ./tests/

# Runtime directories. Declared here so the mount points exist even on a
# first run, and so a forgotten bind mount fails loudly rather than
# silently writing into the image.
RUN mkdir -p /app/data/incidents /app/data/metrics /app/reports/html /app/reports/md

# --- Safety assertions baked into the image ---
# Fail the build rather than ship an image that violates docs/SECURITY.md.
#   1. Host memory capture tools must not be present.
#   2. Live-infrastructure tooling must not be present.
RUN ! command -v DumpIt >/dev/null 2>&1 \
 && ! command -v LiME >/dev/null 2>&1 \
 && ! command -v winpmem >/dev/null 2>&1 \
 && ! command -v avml >/dev/null 2>&1 \
 && ! command -v pwsh >/dev/null 2>&1 \
 && ! command -v powershell >/dev/null 2>&1 \
 && ! command -v nmap >/dev/null 2>&1 \
 && echo "OK: no host-memory-capture or live-infra tooling in image"

EXPOSE 8000

CMD ["uvicorn", "soar.api.main:app", "--host", "0.0.0.0", "--port", "8000"]