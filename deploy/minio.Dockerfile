# syntax=docker/dockerfile:1
# MinIO withdrew its community images and binary downloads. Build the same
# releases used by the test stack from their official, checksummed source.
FROM golang:1.24.2-bookworm@sha256:79390b5e5af9ee6e7b1173ee3eac7fadf6751a545297672916b59bfa0ecf6f71 AS go-build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=2
WORKDIR /build

FROM go-build AS minio-build
# Pinned upstream release commit for RELEASE.2025-09-07T16-13-09Z.
RUN curl --fail --location --show-error --retry 3 \
      https://codeload.github.com/minio/minio/tar.gz/07c3a429bfed433e49018cb0f78a52145d4bedeb -o source.tar.gz \
    && echo '8819e3e7817e46b7b3798f8f200ead208562e571563c2e040352378031abe9f2  source.tar.gz' | sha256sum -c - \
    && tar -xzf source.tar.gz --strip-components=1 \
    && rm source.tar.gz
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go build -p 2 -mod=readonly -trimpath -tags kqueue \
      -ldflags='-s -w -X github.com/minio/minio/cmd.Version=2025-09-07T16:13:09Z -X github.com/minio/minio/cmd.ReleaseTag=RELEASE.2025-09-07T16-13-09Z -X github.com/minio/minio/cmd.CopyrightYear=2025 -X github.com/minio/minio/cmd.CommitID=07c3a429bfed433e49018cb0f78a52145d4bedeb -X github.com/minio/minio/cmd.ShortCommitID=07c3a429bfed' \
      -o /out/minio .

FROM go-build AS mc-build
# Pinned upstream release commit for RELEASE.2025-08-13T08-35-41Z.
RUN curl --fail --location --show-error --retry 3 \
      https://codeload.github.com/minio/mc/tar.gz/7394ce0dd2a80935aded936b09fa12cbb3cb8096 -o source.tar.gz \
    && echo '95cd293c7119f16921a6dc515a1fb74a2227f19fd994b9c8b770a154e802ac44  source.tar.gz' | sha256sum -c - \
    && tar -xzf source.tar.gz --strip-components=1 \
    && rm source.tar.gz
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go build -p 2 -mod=readonly -trimpath -tags kqueue \
      -ldflags='-s -w -X github.com/minio/mc/cmd.Version=2025-08-13T08:35:41Z -X github.com/minio/mc/cmd.ReleaseTag=RELEASE.2025-08-13T08-35-41Z -X github.com/minio/mc/cmd.CopyrightYear=2025 -X github.com/minio/mc/cmd.CommitID=7394ce0dd2a80935aded936b09fa12cbb3cb8096 -X github.com/minio/mc/cmd.ShortCommitID=7394ce0dd2a80' \
      -o /out/mc .

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime
ARG DEBIAN_SNAPSHOT=20260921T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ bookworm main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ bookworm-security main\n' "$DEBIAN_SNAPSHOT" >> /etc/apt/sources.list \
    && apt-get update && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 minio \
    && useradd --system --uid 10001 --gid minio --create-home minio \
    && mkdir /data && chown minio:minio /data
USER minio:minio
WORKDIR /data

FROM runtime AS minio
COPY --from=minio-build /out/minio /usr/local/bin/minio
COPY --from=minio-build /build/LICENSE /usr/share/licenses/minio/LICENSE
LABEL org.opencontainers.image.source="https://github.com/minio/minio" \
      org.opencontainers.image.version="RELEASE.2025-09-07T16-13-09Z" \
      org.opencontainers.image.revision="07c3a429bfed433e49018cb0f78a52145d4bedeb" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
EXPOSE 9000
ENTRYPOINT ["minio"]
CMD ["server", "/data"]

FROM runtime AS mc
COPY --from=mc-build /out/mc /usr/local/bin/mc
COPY --from=mc-build /build/LICENSE /usr/share/licenses/mc/LICENSE
LABEL org.opencontainers.image.source="https://github.com/minio/mc" \
      org.opencontainers.image.version="RELEASE.2025-08-13T08-35-41Z" \
      org.opencontainers.image.revision="7394ce0dd2a80935aded936b09fa12cbb3cb8096" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
ENTRYPOINT ["mc"]
