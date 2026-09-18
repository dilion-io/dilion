# Production image for the Dilion server.
#
#   docker build -t dilion .        # host architecture
#   make docker-build               # same, with the OCI labels filled in
#
# Build context is the repository root, but only the Go module is needed --
# see .dockerignore for what is excluded and why.
#
# Dilion applies its own migrations at startup (dilion.Server.Migrate), so there
# is no separate migrate step, init container, or entrypoint script. This mirrors
# test/parity/Dockerfile.dilion, which builds the same binary for the parity
# stack; keep the two in step.

# --platform=$BUILDPLATFORM pins the toolchain to the *build* architecture and
# cross-compiles to the target instead of emulating it. Go cross-compiles well,
# and this is several times faster than running the compiler under QEMU when the
# release workflow builds amd64 and arm64 together.
FROM --platform=$BUILDPLATFORM golang:1.26.8 AS build

WORKDIR /src

# Module downloads are their own layer, so editing source does not re-download.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# Provided by buildx for each requested platform.
ARG TARGETOS
ARG TARGETARCH

# The build cache is keyed per target architecture; sharing one across arches
# only evicts entries the other arch just wrote.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build,id=go-build-$TARGETARCH \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags='-s -w' -o /out/dilion ./cmd/dilion

# static-debian12 carries no shell and no package manager; :nonroot runs as
# uid 65532. CGO_ENABLED=0 above is what makes this base viable.
FROM gcr.io/distroless/static-debian12:nonroot

# Release metadata. CI passes these; the defaults keep a local build honest
# rather than claiming a version it is not.
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Dilion" \
      org.opencontainers.image.description="Supabase Auth compatible auth plus the privacy/compliance plane" \
      org.opencontainers.image.url="https://github.com/dilion-io/dilion" \
      org.opencontainers.image.source="https://github.com/dilion-io/dilion" \
      org.opencontainers.image.documentation="https://github.com/dilion-io/dilion#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$CREATED"

COPY --from=build /out/dilion /usr/local/bin/dilion

# DILION_DSN is still required at run time; see cmd/dilion/main.go for the full
# environment contract.
ENV DILION_ADDR=:8787
EXPOSE 8787

ENTRYPOINT ["/usr/local/bin/dilion"]
