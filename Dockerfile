# syntax=docker/dockerfile:1
FROM golang:1.22 AS builder
WORKDIR /app

# Copy module definition first for dependency caching
COPY go.mod ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build the statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o wirevault ./...

FROM debian:bookworm-slim AS runtime

# Install minimal certificates for outgoing HTTPS (token export, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV APP_HOME=/app \
    ADDR=:8080

WORKDIR ${APP_HOME}

# Copy application binary and assets
COPY --from=builder /app/wirevault ./wirevault
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Prepare persistent directories for JSON store and uploads
RUN mkdir -p data media \
    && groupadd --system wirevault \
    && useradd --system --gid wirevault --home ${APP_HOME} wirevault \
    && chown -R wirevault:wirevault ${APP_HOME}

USER wirevault

EXPOSE 8080

ENTRYPOINT ["/app/wirevault"]
CMD ["-addr", ":8080"]
