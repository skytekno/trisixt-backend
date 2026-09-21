# Redis 8.10.2 is upstream stable (2026-09-17); its official Docker tag was
# unavailable on 2026-09-19. Build the exact release rather than downgrade.
FROM alpine:3.23 AS builder
RUN apk add --no-cache build-base linux-headers openssl-dev curl
WORKDIR /build
RUN curl --fail --location --show-error --user-agent 'Mozilla/5.0' \
      https://download.redis.io/releases/redis-8.10.2.tar.gz -o redis.tar.gz \
    && echo 'b9ffee226b5eecdba98a679260dad764b2a4ebd90dce4ad5ac9e9f3eef9c02b3  redis.tar.gz' | sha256sum -c - \
    && tar -xzf redis.tar.gz \
    && make -C redis-8.10.2/src -j2 MALLOC=libc BUILD_TLS=yes USE_SYSTEMD=no redis-server redis-cli \
    && ./redis-8.10.2/src/redis-server --version | grep 'v=8.10.2'

FROM alpine:3.23
RUN apk add --no-cache libssl3 libcrypto3 \
    && addgroup -S redis && adduser -S -G redis redis \
    && mkdir /data && chown redis:redis /data
COPY --from=builder /build/redis-8.10.2/src/redis-server /usr/local/bin/redis-server
COPY --from=builder /build/redis-8.10.2/src/redis-cli /usr/local/bin/redis-cli
COPY --from=builder /build/redis-8.10.2/LICENSE.txt /usr/share/licenses/redis/LICENSE.txt
USER redis
WORKDIR /data
EXPOSE 6379
CMD ["redis-server", "--appendonly", "yes"]
