#!/usr/bin/env bash
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"

echo "Configuring Vault at $VAULT_ADDR"

export VAULT_ADDR VAULT_TOKEN

vault auth enable kubernetes || true
vault secrets enable -path=kidring kv-v2 || true

echo "Vault setup complete"
