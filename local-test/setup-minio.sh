#!/usr/bin/env bash
set -euo pipefail

MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
BUCKET="${BUCKET:-kidring}"

echo "Setting up MinIO bucket: $BUCKET"

# Install mc if not present
if ! command -v mc &>/dev/null; then
  echo "Please install MinIO client (mc)"
  exit 1
fi

mc alias set local "$MINIO_ENDPOINT" minioadmin minioadmin
mc mb --ignore-existing "local/$BUCKET"
mc anonymous set download "local/$BUCKET/.well-known"
echo "MinIO setup complete"
