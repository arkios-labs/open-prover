#!/bin/bash
set -e

echo "Checking if 'zig' is installed..."
if ! command -v zig &> /dev/null; then
    echo "Installing zig via Homebrew..."
    brew install zig
fi

echo "Checking if 'cargo-zigbuild' is installed..."
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install --locked cargo-zigbuild
fi

echo "Ensuring Rust MUSL target is added..."
rustup target add x86_64-unknown-linux-musl

echo "Building r0_prover for arm64..."
cargo build --release
cp ../target/release/r0_prover ../r0_prover_arm64

echo "Building r0_prover for x86_64-unknown-linux-musl..."
cargo zigbuild --target x86_64-unknown-linux-musl --release
cp ../target/x86_64-unknown-linux-musl/release/r0_prover ../r0_prover_amd64

echo "Build complete. Artifacts:"
ls -lh ../r0_prover_*
