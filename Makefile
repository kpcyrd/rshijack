build:
	repro-env build -- sh -c ' \
	RUSTFLAGS="-C strip=symbols" \
	cargo build --target x86_64-unknown-linux-musl --release'

.PHONY: build
