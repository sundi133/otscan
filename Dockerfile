FROM python:3.11-slim

LABEL maintainer="otscan"
LABEL description="OTScan - OT/ICS/SCADA Network Security Scanner"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    nmap \
    iputils-ping \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/otscan

# Copy dependency file first for layer caching
COPY pyproject.toml .
COPY README.md .

# Install Python package in editable mode with all extras
COPY . .
RUN pip install --no-cache-dir -e ".[dev,full]"

# Verify installation
RUN otscan --version && \
    python -m pytest --co -q tests/ 2>/dev/null | tail -1

ENTRYPOINT ["otscan"]
CMD ["--help"]
