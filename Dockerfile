# syntax=docker/dockerfile:1.6

# Build stage
FROM golang:1.24.3 AS builder
WORKDIR /app

# Enable module download caching
COPY go.mod go.sum ./
RUN go mod download

# Copy application source
COPY . .

# Ensure runtime directories exist for local testing and container copies
RUN mkdir -p data media

# Build the binary
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -o wirevault ./

# Runtime stage
FROM gcr.io/distroless/base-debian12
WORKDIR /app

# Copy binary and required assets
COPY --from=builder /app/wirevault ./wirevault
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY --from=builder /app/data ./data
COPY --from=builder /app/media ./media

# Expose the HTTP port
EXPOSE 8080

ENTRYPOINT ["/app/wirevault"]
CMD ["-addr", ":8080"]
