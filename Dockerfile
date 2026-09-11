ARG NODE_VERSION=22
ARG GO_VERSION=1.26.6
ARG ALPINE_VERSION=3.22

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS frontend
WORKDIR /src/frontend
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --ignore-scripts
COPY frontend/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS go-base
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY
WORKDIR /src

FROM go-base AS go-deps
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

FROM go-deps AS builder
ARG TARGETOS
ARG TARGETARCH
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY web/ ./web/
COPY --from=frontend /src/frontend/dist/ ./web/dist/
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/nocyber-guard ./cmd/nocyber-guard

FROM go-base AS e2e-builder
COPY .github/e2e/ /e2e-src/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fake-upstream /e2e-src/fake-upstream/main.go \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/e2e-client /e2e-src/client/main.go

FROM alpine:${ALPINE_VERSION} AS e2e-upstream
RUN addgroup -S -g 65532 e2e && adduser -S -D -H -u 65532 -G e2e e2e
COPY --from=e2e-builder /out/fake-upstream /usr/local/bin/fake-upstream
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/fake-upstream"]

FROM alpine:${ALPINE_VERSION} AS e2e-client
RUN addgroup -S -g 65532 e2e && adduser -S -D -H -u 65532 -G e2e e2e
COPY --from=e2e-builder /out/e2e-client /usr/local/bin/e2e-client
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/e2e-client"]

FROM alpine:${ALPINE_VERSION} AS runtime
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine
LABEL org.opencontainers.image.title="NoCyber Guard" \
    org.opencontainers.image.description="Platform-independent transparent instruction-audit proxy" \
    org.opencontainers.image.url="https://github.com/abingooo/nocyber-guard" \
    org.opencontainers.image.source="https://github.com/abingooo/nocyber-guard" \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE \
    org.opencontainers.image.licenses="LGPL-3.0-or-later"
RUN sed -i "s?https://dl-cdn.alpinelinux.org/alpine?${APK_MIRROR}?" /etc/apk/repositories \
    && apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 65532 nocyber \
    && adduser -S -D -H -u 65532 -G nocyber nocyber \
    && install -d -o 65532 -g 65532 -m 0700 /data \
    && install -d -o 0 -g 0 -m 0755 /licenses
COPY --from=builder /out/nocyber-guard /usr/local/bin/nocyber-guard
COPY LICENSE NOTICE /licenses/

USER 65532:65532
WORKDIR /data
ENV NCG_LISTEN_ADDR=0.0.0.0:8080 \
    NCG_ADMIN_LISTEN_ADDR=0.0.0.0:9090 \
    NCG_DATA_DIR=/data \
    TZ=Asia/Shanghai
EXPOSE 8080 9090
VOLUME ["/data"]
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
    CMD wget -q -O - http://127.0.0.1:8080/_nocyber/readyz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/nocyber-guard"]
