# Local Test Environment

This directory contains scripts and configuration for running kube-oidc-fed locally with MinIO (mock S3) and Vault (OIDC federation testing).

## Prerequisites

- Docker and Docker Compose
- `mc` (MinIO client) — [install](https://min.io/docs/minio/linux/reference/minio-mc.html)
- `vault` CLI — [install](https://developer.hashicorp.com/vault/downloads)
- `jq`
- `curl`

## Quick Start

```bash
# Start MinIO, Vault and registry
docker-compose up -d

# Wait for services to start
sleep 5

# Set up MinIO bucket (creates 'kube-oidc-fed' bucket with public .well-known/ prefix)
./setup-minio.sh

# Configure Vault JWT auth pointing at the local registry
REGISTRY_ISSUER=http://localhost:8080 ./setup-vault.sh

# Run the end-to-end flow test
./test-flow.sh
```

## Components

- **MinIO**: S3-compatible object storage
  - API: http://localhost:9000
  - Console: http://localhost:9001 (login: minioadmin / minioadmin)
- **Vault**: HashiCorp Vault in dev mode for OIDC federation testing
  - UI: http://localhost:8200
  - Root token: `root`
- **Registry**: kube-oidc-fed registry service
  - API: http://localhost:8080

## Credentials

- MinIO: `minioadmin` / `minioadmin`
- Registry auth token: `local-test-token`
- Vault root token: `root`

## Testing Vault JWT Federation

After running the setup scripts, you can test Vault JWT auth:

```bash
# Get the signed JWT from a test broker (or use the test-flow.sh output)
JWT="<your-signed-jwt>"

# Authenticate to Vault using the JWT
vault write auth/jwt/login role=kube-oidc-fed-test jwt="$JWT"

# Read the test secret
vault kv get secret/test/config
```

## Architecture

```
Workload → kube-oidc-fed-broker (local binary) → POST /token/exchange
                                        ← signed JWT

kube-oidc-fed-broker startup:
  1. Generate EC P-256 key pair
  2. POST /register → get presigned S3 URL
  3. PUT JWK to MinIO (simulates S3)

AWS/GCP/Vault:
  1. Fetch /.well-known/openid-configuration from registry
  2. Fetch /.well-known/jwks.json from registry (backed by MinIO)
  3. Verify JWT signature using the JWKS
```

