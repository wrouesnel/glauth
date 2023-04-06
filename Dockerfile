# Dockerfile for building the containerized poller_exporter
# golang:1.18 as of 2022-07-04
FROM ubuntu AS build

MAINTAINER William Rouesnel <wrouesnel@wrouesnel.com>

COPY ./ /workdir/
WORKDIR /workdir

RUN \
    apt update \
 && apt install -y ldap-utils oathtool libpam0g-dev golang ca-certificates git

RUN go run mage.go binary

FROM ubuntu

EXPOSE 389 636 5555
MAINTAINER Will Rouesnel <wrouesnel@wrouesnel.com>

RUN \
    apt update \
 && apt install -y ldap-utils oathtool libpam0g ca-certificates

ENV PATH=/bin
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs
COPY --from=build /workdir/glauth /bin/glauth
COPY ./docker-default.cfg /config/config.cfg

ENTRYPOINT ["/bin/glauth"]
CMD ["-c", "/config/config.cfg"]
