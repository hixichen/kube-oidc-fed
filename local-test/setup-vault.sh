#!/usr/bin/env bash
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
REGISTRY_ISSUER="${REGISTRY_ISSUER:-http://localhost:8080}"

echo "Configuring Vault at $VAULT_ADDR"

export VAULT_ADDR VAULT_TOKEN

# Enable JWT auth method for OIDC federation
vault auth enable jwt 2>/dev/null || echo "JWT auth already enabled"

# Configure JWT auth with our registry as the OIDC provider
vault write auth/jwt/config \
  oidc_discovery_url="${REGISTRY_ISSUER}" \
  default_role="kube-oidc-fed-test"

# Create a test policy
vault policy write kube-oidc-fed-test - <<EOF
path "secret/data/test/*" {
  capabilities = ["read"]
}
EOF

# Create a test role that trusts tokens from the kube-oidc-fed issuer
vault write auth/jwt/role/kube-oidc-fed-test \
  role_type="jwt" \
  bound_issuer="${REGISTRY_ISSUER}" \
  user_claim="sub" \
  policies="kube-oidc-fed-test" \
  ttl="1h"

# Create a sample secret for testing
vault kv put secret/test/config value="hello-from-vault"

echo "Vault setup complete"
echo "  OIDC discovery: ${REGISTRY_ISSUER}/.well-known/openid-configuration"
echo "  JWT auth role:  kube-oidc-fed-test"
echo "  Test secret:    secret/test/config"
