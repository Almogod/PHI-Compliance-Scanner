# Production Dockerfile for PHI Compliance Scanner v4.0 (Zero-Trust Air-Gapped Container)
FROM python:3.11-slim

# Prevent Python from writing bytecode and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy metadata files and offline wheels
COPY pyproject.toml /app/
COPY wheels/ /app/wheels/

# Install runtime dependencies 100% offline from local wheels
RUN pip install --no-cache-dir --no-index --find-links=/app/wheels click openpyxl python-docx pypdf cryptography 2>/dev/null || \
    pip install --no-cache-dir --no-index --find-links=/app/wheels click openpyxl python-docx pypdf

# Copy source code
COPY src/ /app/src/

# Install local package offline
RUN pip install --no-deps --no-build-isolation -e .

# Create non-root compliance user for security best practice
RUN useradd -m compliance && chown -R compliance:compliance /app
USER compliance

# Mount target directory into /data
VOLUME ["/data"]

ENTRYPOINT ["scan"]
CMD ["/data", "--output", "/data/audit_report.html"]
