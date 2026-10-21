# Multi-stage Docker build for FastFlow Container Image (GitHub Packages)
FROM python:3.12-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .

# Build and install wheel
RUN pip install --no-cache-dir maturin
RUN pip install --no-cache-dir .

# Final slim runtime image
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="FastFlow" \
      org.opencontainers.image.description="Ultra-high-performance zero-copy network telemetry & PCAP engine" \
      org.opencontainers.image.source="https://github.com/rdxkeerthi/fastflow" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY examples/analyze_pcap.py /usr/local/bin/fastflow-analyze
RUN chmod +x /usr/local/bin/fastflow-analyze

WORKDIR /data
ENTRYPOINT ["python", "/usr/local/bin/fastflow-analyze"]
