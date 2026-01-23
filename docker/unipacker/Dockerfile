# Unipacker Docker Image
# Emulation-based automatic unpacker for Windows PE binaries
# Uses Unicorn Engine for platform-independent unpacking

FROM python:3.11-slim

LABEL maintainer="Sentinel Project"
LABEL description="Unipacker emulation-based PE unpacker"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Install unipacker and dependencies
RUN pip install --no-cache-dir \
    unipacker==1.0.8 \
    yara-python

# Create working directories
RUN mkdir -p /workspace/input /workspace/output

WORKDIR /workspace

# Create entrypoint script for CLI and API modes
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Default command: run unipacker on input file
ENTRYPOINT ["/entrypoint.sh"]
