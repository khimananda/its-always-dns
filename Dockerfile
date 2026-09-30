# Built by GoReleaser from a prebuilt binary. Distroless static, non-root,
# so the image scores well on docker-nutrition-facts too.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/its-always-dns /usr/local/bin/its-always-dns
ENTRYPOINT ["/usr/local/bin/its-always-dns"]
