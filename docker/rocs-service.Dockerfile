# syntax=docker/dockerfile:1
#
# Reference rocs service image.
#
# This Dockerfile intentionally delegates compilation to the repository build
# script. The builder image must provide the ncc compiler; the standard
# n00b-linux toolchain image produced from docker/Dockerfile is the expected
# local builder.

ARG BUILDER_IMAGE=n00b-linux:latest
ARG RUNTIME_IMAGE=ubuntu:plucky

FROM ${BUILDER_IMAGE} AS build
WORKDIR /src

COPY . /src

ARG NCC_PATH=/usr/local/bin/ncc
ENV NCC_PATH=${NCC_PATH}
RUN N00B_NATIVE=1 \
    N00B_SKIP_VCS_CHECK=1 \
    N00B_TEST=0 \
    N00B_BUILD_TARGETS=n00b-rocs-service \
    bash /src/build.sh /tmp/n00b-rocs-service-build

FROM ${RUNTIME_IMAGE}

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/rocs --create-home rocs \
    && mkdir -p /var/cache/rocs \
    && chown -R rocs:rocs /var/lib/rocs /var/cache/rocs

COPY --from=build /tmp/n00b-rocs-service-build/n00b-rocs-service \
    /usr/local/bin/n00b-rocs-service

ENV ROCS_PROFILE=service_s3
ENV ROCS_HTTP_ADDR=0.0.0.0:8080
ENV ROCS_CACHE_DIR=/var/cache/rocs

USER 10001:10001
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/n00b-rocs-service"]
CMD ["--serve"]
