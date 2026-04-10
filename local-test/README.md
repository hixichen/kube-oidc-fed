# Local Test Environment

This directory contains scripts and configuration for running kube-kidring locally.

## Prerequisites

- Docker and Docker Compose
- `mc` (MinIO client)
- `jq`
- `curl`

## Quick Start

```bash
# Start MinIO and registry
docker-compose up -d

# Set up MinIO bucket
./setup-minio.sh

# Run the flow test
./test-flow.sh
```

## Components

- **MinIO**: S3-compatible object storage (accessible at http://localhost:9000, console at http://localhost:9001)
- **Registry**: kube-kidring registry service (accessible at http://localhost:8080)

## Credentials

- MinIO: `minioadmin` / `minioadmin`
- Registry auth token: `local-test-token`
