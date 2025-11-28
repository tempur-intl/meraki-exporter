FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies and generate go.sum
RUN go mod download && go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o meraki-exporter .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/meraki-exporter .

# Expose metrics port
EXPOSE 9100

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:9100/health || exit 1

# Run as non-root user
RUN addgroup -g 1000 exporter && \
    adduser -D -u 1000 -G exporter exporter && \
    chown -R exporter:exporter /root

USER exporter

CMD ["./meraki-exporter"]
