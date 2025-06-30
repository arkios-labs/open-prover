#!/bin/bash

set -e

# Define target directory and image tag
SNARK_DIR="/home/ubuntu/snark"
DOCKER_IMAGE="risczero/risc0-groth16-prover:v2025-04-03.1"
CONTAINER_NAME="temp-prover"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
  echo "Docker is not installed. Please install Docker first."
  exit 1
fi

# Create target directory if it doesn't exist
if [ ! -d "$SNARK_DIR" ]; then
  echo "Directory $SNARK_DIR does not exist. Creating it now."
  mkdir -p "$SNARK_DIR"
fi

# Pull the Docker image
echo "Pulling Docker image: $DOCKER_IMAGE"
docker pull "$DOCKER_IMAGE"

# Create a temporary container
echo "Creating temporary container: $CONTAINER_NAME"
docker create --name "$CONTAINER_NAME" "$DOCKER_IMAGE"

# Copy required files
echo "Copying files from the container..."
docker cp "$CONTAINER_NAME":/usr/local/bin/stark_verify "$SNARK_DIR/"
docker cp "$CONTAINER_NAME":/app/stark_verify.dat "$SNARK_DIR/"
docker cp "$CONTAINER_NAME":/usr/local/bin/prover "$SNARK_DIR/"
docker cp "$CONTAINER_NAME":/app/stark_verify.cs "$SNARK_DIR/"
docker cp "$CONTAINER_NAME":/app/stark_verify_final.pk.dmp "$SNARK_DIR/"

# Remove the temporary container
echo "Removing temporary container..."
docker rm "$CONTAINER_NAME"

echo "All files have been successfully copied to $SNARK_DIR"
