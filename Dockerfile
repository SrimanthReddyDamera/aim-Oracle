# =============================================================================
# ORACLE Enterprise Runtime Containerfile (Brick 4.6)
# Hardened, non-root, multi-stage container specification
# =============================================================================

# --- Stage 1: Build & Dependency Resolution ---
FROM python:3.11-slim as builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /build/requirements.txt
RUN pip install --user --no-cache-dir -r requirements.txt


# --- Stage 2: Final Minimal Hardened Runtime ---
FROM python:3.11-slim as runtime

LABEL maintainer="ORACLE Architecture Team <oracle@corp.internal>" \
      version="4.6.0" \
      description="ORACLE Live Enterprise Operations & Distributed Control Plane"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/oracle/.local/bin:$PATH" \
    PYTHONPATH="/app" \
    ORACLE_ENV="production" \
    ORACLE_REQUIRE_HTTPS="true"

# Security: Create non-root user 'oracle' with UID/GID 10001
RUN groupadd -g 10001 oracle && \
    useradd -u 10001 -g oracle -m -s /bin/bash oracle && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/oracle/.local

# Copy application source code with ownership
COPY --chown=oracle:oracle backend /app/backend
COPY --chown=oracle:oracle deploy /app/deploy

# Setup entrypoint permissions
RUN chmod +x /app/deploy/docker/entrypoint.sh && \
    chown -R oracle:oracle /home/oracle /app

# Switch to non-root user
USER 10001:10001

# Healthcheck targeting decoupled liveness probe
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

EXPOSE 8000

ENTRYPOINT ["/app/deploy/docker/entrypoint.sh"]
CMD ["api"]
