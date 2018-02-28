FROM rust:latest
WORKDIR /usr/src/rshijack
COPY . .
RUN cargo build --release --verbose \
    && strip target/release/rshijack
FROM busybox:1-glibc
COPY --from=0 /usr/src/rshijack/target/release/rshijack /usr/local/bin/rshijack
COPY --from=0 /lib/x86_64-linux-gnu/libdl.so.2 \
    /lib/x86_64-linux-gnu/librt.so.1 \
    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
    /lib/x86_64-linux-gnu/
ENTRYPOINT ["rshijack"]
