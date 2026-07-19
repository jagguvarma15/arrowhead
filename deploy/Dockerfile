# Multi-stage build: dependencies resolved with uv in the builder, then a
# slim runtime image that runs as a non-root user.
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.2 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Install dependencies first against the lockfile so this layer caches
# across source changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# Then install the project itself.
COPY src ./src
COPY README.md ./
RUN uv sync --frozen --no-dev


FROM python:3.12-slim AS runtime

# Unprivileged user; the app never needs root.
RUN groupadd --system arrowhead \
    && useradd --system --gid arrowhead --home /app arrowhead

WORKDIR /app

COPY --from=builder --chown=arrowhead:arrowhead /app /app

# Corpus mount points, owned by the non-root user so the process can write
# when a volume or disk is mounted here. A named Docker volume inherits this
# ownership on first use; platform disks (Render, Fly) mount over the path.
RUN mkdir -p /app/documents /var/lib/arrowhead/documents \
    && chown -R arrowhead:arrowhead /app/documents /var/lib/arrowhead

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    ARROWHEAD_TRANSPORT=http \
    ARROWHEAD_HOST=0.0.0.0 \
    ARROWHEAD_PORT=8000

USER arrowhead

EXPOSE 8000

# The platform terminates TLS in front of this process.
CMD ["python", "-m", "arrowhead.server"]
