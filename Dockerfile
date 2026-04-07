# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Prevent Python from writing .pyc files & enable logs immediately
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

# Install dependencies into a separate directory
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Same env in runtime (important)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create non-root user (security best practice)
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

EXPOSE 5000

# Run using Gunicorn (Flask factory pattern)
CMD ["gunicorn", "app:create_app", \
     "--workers", "4", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--factory"]