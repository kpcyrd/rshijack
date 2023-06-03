FROM rust:alpine3.17
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN apk add musl-dev
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/rshijack .
RUN strip rshijack

FROM alpine:3.17
RUN apk add --no-cache libgcc
COPY --from=0 /app/rshijack /usr/local/bin/rshijack
ENTRYPOINT ["rshijack"]
