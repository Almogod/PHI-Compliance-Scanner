# Production Dockerfile for PHI Compliance Scanner v3.0 (Zero-Trust Air-Gapped Container)
FROM python:3.11-slim

# Prevent Python from writing bytecode and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and source code
COPY pyproject.toml /app/
COPY src/ /app/src/
COPY docs/ /app/docs/

# Install PHI scanner package locally
RUN pip install --no-cache-dir .

# Create non-root compliance user for security best practice
RUN useradd -m compliance && chown -R compliance:compliance /app
USER compliance

# Mount target directory into /data
VOLUME ["/data"]

ENTRYPOINT ["scan"]
CMD ["/data", "--output", "/data/audit_report.html"]
