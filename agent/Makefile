.PHONY: all check-tools arm amd64

all: check-tools arm amd64

check-tools:
	@command -v zig >/dev/null || (echo "Installing zig..." && brew install zig)
	@command -v cargo-zigbuild >/dev/null || (echo "Installing cargo-zigbuild..." && cargo install --locked cargo-zigbuild)
	@rustup target add x86_64-unknown-linux-musl

arm:
	cargo build --release
	cp ./target/release/r0_prover ./r0_prover_arm64

amd64:
	cargo zigbuild --target x86_64-unknown-linux-musl --release
	cp ./target/x86_64-unknown-linux-musl/release/r0_prover ./r0_prover_amd64