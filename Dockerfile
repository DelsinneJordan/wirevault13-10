# --- Build stage ---
# Pin to a Go version that satisfies go.mod
ARG GO_VERSION=1.24.3
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /app

# Cache deps first
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source and build a static binary
COPY . .
ENV CGO_ENABLED=0 GOOS=linux
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o wirevault .

# --- Runtime stage ---
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user first so we can set ownership properly
RUN useradd -r -u 10001 appuser

WORKDIR /app

# Create data dirs and set ownership
RUN mkdir -p /app/data /app/media \
 && chown -R appuser:appuser /app

# Copy the binary with correct ownership
COPY --chown=10001:10001 --from=builder /app/wwirevault /app/wirevault

USER appuser

EXPOSE 8080
ENV ADDR=:8080

ENTRYPOINT ["/app/wirevault"]

# Copy binary
COPY --from=builder /app/wirevault /app/wirevault

# Non-root user
RUN useradd -r -u 10001 appuser
USER appuser

# App listens on 8080
EXPOSE 8080
ENV ADDR=:8080

ENTRYPOINT ["/app/wirevault"]
