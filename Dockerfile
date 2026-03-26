# Build stage
FROM rust:1.88-bookworm AS builder

WORKDIR /usr/src/meridian
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/meridian/target/release/meridian /usr/local/bin/meridian
COPY meridian.toml.example /etc/meridian/meridian.toml

EXPOSE 53/udp 53/tcp 9053/tcp

ENTRYPOINT ["meridian"]
CMD ["--config", "/etc/meridian/meridian.toml"]
