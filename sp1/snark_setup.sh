#!/bin/bash
set -euo pipefail

VERSION="${SP1_CIRCUIT_VERSION:-v5.0.0}"
DEST_DIR="$HOME/.sp1/circuits"
BASE_URL="https://sp1-circuits.s3-us-east-2.amazonaws.com"

download_and_extract() {
    local type=$1
    local target_dir="${DEST_DIR}/${type}/${VERSION}"

    if [ -d "$target_dir" ]; then
        echo "[SKIP] ${type} artifacts for ${VERSION} already exist at ${target_dir}"
        return
    fi

    echo "[DOWNLOAD] ${type} artifacts for ${VERSION}..."
    mkdir -p "$target_dir"
    curl -L -o "/tmp/${type}.tar.gz" "${BASE_URL}/${VERSION}-${type}.tar.gz"
    tar -Pxzf "/tmp/${type}.tar.gz" -C "$target_dir"
    echo "[DONE] ${type} artifacts extracted to ${target_dir}"
}

download_and_extract "groth16"
download_and_extract "plonk"

echo "All artifacts are prepared under $DEST_DIR"
