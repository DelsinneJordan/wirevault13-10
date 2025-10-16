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

WORKDIR /app
# Non-root user
RUN useradd -r -u 10001 appuser

# Folders for persisted data
# Prepare persisted directories with relaxed permissions so the runtime
# user (and external volume mounts) can write to them safely.
RUN mkdir -p /app/data /app/media \
    && chown -R appuser:appuser /app/data /app/media \
    && chmod 0775 /app/data /app/media

# Copy binary and runtime assets
COPY --from=builder /app/wirevault /app/wirevault
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static

USER appuser

# App listens on 8080
EXPOSE 8080

ENTRYPOINT ["/app/wirevault"]
CMD ["-addr", ":8080"]
