#!/usr/bin/env bash
# Quick single-container dev run of kube-oidc-fed-registry using in-memory store.
# No docker-compose or MinIO required.
set -e

IMAGE=${REGISTRY_IMAGE:-kube-oidc-fed-registry:latest}
PORT=${PORT:-8080}
AUTH_TOKEN=${REGISTRY_AUTH_TOKEN:-dev-token}
ISSUER=${REGISTRY_ISSUER:-http://localhost:${PORT}}

echo "Starting kube-oidc-fed-registry (in-memory) on port ${PORT}"
echo "Auth token: ${AUTH_TOKEN}"
echo "Issuer:     ${ISSUER}"

docker run --rm \
  -p "${PORT}:8080" \
  -e REGISTRY_MEMORY=true \
  -e REGISTRY_AUTH_TOKEN="${AUTH_TOKEN}" \
  -e REGISTRY_ISSUER="${ISSUER}" \
  "${IMAGE}"
