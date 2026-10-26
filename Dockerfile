# Builds on the host platform and cross-compiles for the target, so multi-arch
# builds don't run the Go toolchain under emulation. The binary has no cgo, so
# it runs on a static base image.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum go.work ./
COPY v2/go.mod v2/go.sum ./v2/
RUN go mod download && cd v2 && go mod download

COPY . .
RUN go run mage.go releaseBin "${TARGETOS}-${TARGETARCH}" \
    && mkdir /out \
    && cp bin/*_"${TARGETOS}-${TARGETARCH}"/* /out/

# Runs as root: it binds ports below 1024 and the unix backend reads shadow.
FROM gcr.io/distroless/static-debian13

LABEL org.opencontainers.image.title="GLAuth" \
      org.opencontainers.image.description="A simple LDAP server with config, SQL, LDAP proxy and Unix account backends" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/glauth /bin/glauth
COPY docker-default.cfg /config/config.cfg

EXPOSE 389 636 5555

ENTRYPOINT ["/bin/glauth"]
CMD ["-c", "/config/config.cfg"]
