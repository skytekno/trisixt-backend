# syntax=docker/dockerfile:1
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release && cp target/release/trisixt /build/trisixt

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime
ARG DEBIAN_SNAPSHOT=20260921T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ bookworm main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ bookworm-security main\n' "$DEBIAN_SNAPSHOT" >> /etc/apt/sources.list \
    && apt-get update && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 trisixt \
    && useradd --system --uid 10001 --gid trisixt --create-home trisixt
WORKDIR /app
COPY --from=builder /build/trisixt /usr/local/bin/trisixt
COPY LICENSE /app/LICENSE
COPY ee/LICENSE /app/EE-LICENSE
ENV APP_ENV=production HOST=0.0.0.0 PORT=3000 TRISIXT_EE=true
LABEL org.opencontainers.image.title="Trisixt"
STOPSIGNAL SIGTERM
USER trisixt:trisixt
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:3000/up || exit 1
ENTRYPOINT ["trisixt"]
CMD ["serve"]
