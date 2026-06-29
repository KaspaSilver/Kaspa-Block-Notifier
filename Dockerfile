# ── kaspa-block-notifier Dockerfile ──────────────────────────────────────────
# Builds a small Python container that:
#   1. Installs grpcio, grpcio-tools, and the Kaspa Python SDK
#   2. Compiles your proto files into Python stubs
#   3. Runs watcher.py on startup
#
# USAGE:
#   Place your proto files (messages.proto, rpc.proto, p2p.proto) in ./proto/
#   Then: docker compose up -d
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

WORKDIR /app

# ── System deps (needed by some grpcio builds on ARM) ────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps ───────────────────────────────────────────────────────────────
# grpcio-tools  : protoc compiler wrapper
# kaspa         : official Kaspa Python SDK (Rust-backed via PyO3)
# cryptography  : secp256k1 helpers used by the SDK
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Proto compilation ─────────────────────────────────────────────────────────
# Copy all .proto files from your local ./proto/ directory into the image
# and compile them to Python stubs right here at build time.
COPY proto/ ./proto/

RUN python -m grpc_tools.protoc \
        -I./proto \
        --python_out=. \
        --grpc_python_out=. \
        ./proto/messages.proto \
        ./proto/rpc.proto \
    && echo "Proto files compiled successfully."

# ── Application code ──────────────────────────────────────────────────────────
COPY watcher.py .

# ── Runtime ───────────────────────────────────────────────────────────────────
# Unbuffered output so logs appear immediately in `docker logs`
ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "watcher.py"]
