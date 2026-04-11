#!/usr/bin/env bash
set -euo pipefail

REGISTRY_URL="${REGISTRY_URL:-http://localhost:8080}"
AUTH_TOKEN="${AUTH_TOKEN:-local-test-token}"

echo "=== Testing kube-kidring flow ==="

echo "1. Health check"
curl -sf "$REGISTRY_URL/healthz" && echo " OK"

echo "2. Discovery document"
curl -sf "$REGISTRY_URL/.well-known/openid-configuration" | jq .

echo "3. JWKS endpoint"
curl -sf "$REGISTRY_URL/.well-known/jwks.json" | jq .

echo "4. Register a test key"
curl -sf -X POST "$REGISTRY_URL/register" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "kid": "test-kid-1",
    "jwk": {"kty":"EC","crv":"P-256","x":"abc","y":"def","kid":"test-kid-1","alg":"ES256","use":"sig"}
  }' | jq .

echo "5. JWKS after registration"
curl -sf "$REGISTRY_URL/.well-known/jwks.json" | jq .

echo "=== Flow test complete ==="
