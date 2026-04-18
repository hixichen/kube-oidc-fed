# kube-oidc-fed: Staged Implementation Plan

## Overview

This document defines a staged implementation plan for `kube-oidc-fed`, a federated workload identity token exchange system. The project consists of two main components:

1. **kube-oidc-fed-broker** — runs per-cluster, generates signing keys, registers public keys, and signs federated JWTs for workloads.
2. **kube-oidc-fed-registry** — runs centrally, manages public key registration, and serves OIDC discovery + JWKS endpoints backed by S3.

**Language**: Go (Golang)
**Key Libraries**:
- `k8s.io/client-go` — Kubernetes API interaction (Secrets, TokenReview)
- `k8s.io/apimachinery` — Kubernetes object types
- `sigs.k8s.io/controller-runtime` (optional) — for a more declarative controller pattern
- `github.com/aws/aws-sdk-go-v2` — AWS S3 pre-signed URLs and S3 operations
- `github.com/golang-jwt/jwt/v5` — JWT creation and validation
- `github.com/go-jose/go-jose/v4` — JWKS/JWK serialization
- `crypto/ecdsa`, `crypto/elliptic`, `crypto/x509` — EC P-256 key operations
- `net/http` / `github.com/gorilla/mux` or `net/http` (stdlib) — HTTP server

---

## Stage 0: Project Scaffolding & Core Crypto

**Goal**: Establish project structure, Go module, and the foundational cryptographic primitives shared by both components.

### Tasks

- [ ] Initialize Go module (`go mod init github.com/hixichen/kube-oidc-fed`)
- [ ] Define project directory layout:
  ```
  kube-oidc-fed/
  ├── cmd/
  │   ├── agent/          # agent entrypoint
  │   │   └── main.go
  │   └── registry/       # registry entrypoint
  │       └── main.go
  ├── pkg/
  │   ├── crypto/         # key generation, kid derivation, JWT signing
  │   │   ├── keys.go
  │   │   ├── keys_test.go
  │   │   ├── jwt.go
  │   │   └── jwt_test.go
  │   ├── jwks/           # JWK/JWKS types and serialization
  │   │   ├── jwks.go
  │   │   └── jwks_test.go
  │   ├── oidc/           # OIDC discovery document types
  │   │   └── discovery.go
  │   ├── store/          # S3 storage abstraction (registry side)
  │   │   ├── store.go
  │   │   ├── s3.go
  │   │   ├── s3_test.go
  │   │   ├── memory.go   # in-memory implementation for testing
  │   │   └── memory_test.go
  │   ├── agent/          # agent business logic
  │   │   ├── agent.go
  │   │   ├── agent_test.go
  │   │   ├── handler.go
  │   │   └── handler_test.go
  │   ├── registry/       # registry business logic
  │   │   ├── registry.go
  │   │   ├── registry_test.go
  │   │   ├── handler.go
  │   │   └── handler_test.go
  │   └── config/         # shared configuration types
  │       └── config.go
  ├── deploy/
  │   ├── agent/          # Kubernetes manifests for agent
  │   └── registry/       # Kubernetes manifests / Helm charts for registry
  ├── Dockerfile.agent
  ├── Dockerfile.registry
  ├── Makefile
  ├── plan.md
  └── readme.md
  ```
- [ ] Implement `pkg/crypto/keys.go`:
  - `GenerateKeyPair() (*ecdsa.PrivateKey, error)` — generate EC P-256 key pair
  - `DeriveKID(pub *ecdsa.PublicKey) (string, error)` — `sha256(public_key_der)[0:16]`
  - `MarshalPrivateKeyPEM(key *ecdsa.PrivateKey) ([]byte, error)` — PEM encode private key
  - `UnmarshalPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error)` — PEM decode private key
- [ ] Implement `pkg/crypto/jwt.go`:
  - `SignToken(key *ecdsa.PrivateKey, kid string, claims Claims) (string, error)` — sign a JWT with ES256
  - `Claims` struct: `Issuer`, `Subject`, `Audience`, `ClusterID`, `ExpiresAt`, `IssuedAt`, `NotBefore`
- [ ] Implement `pkg/jwks/jwks.go`:
  - `PublicKeyToJWK(pub *ecdsa.PublicKey, kid string) (*JWK, error)` — convert EC public key to JWK JSON structure
  - `BuildJWKS(jwks []*JWK) *JWKS` — aggregate multiple JWKs into a JWKS document
  - Types: `JWK`, `JWKS`
- [ ] Implement `pkg/oidc/discovery.go`:
  - `NewDiscoveryDocument(issuer string) *DiscoveryDocument`
  - `DiscoveryDocument` struct matching the OIDC discovery spec
- [ ] Write unit tests for all of the above
- [ ] Add `Makefile` with targets: `build`, `test`, `lint`, `docker-build`

### Deliverables
- Go module builds cleanly
- `kid` derivation matches spec: `sha256(DER-encoded public key)[:16]` hex string
- JWT signing produces tokens verifiable with the corresponding public key
- JWK/JWKS serialization produces valid JSON consumable by AWS/GCP

---

## Stage 1: kube-oidc-fed-registry — Core API & S3 Storage

**Goal**: Implement the registry as a standalone HTTP server that accepts key registrations and serves OIDC endpoints.

### Tasks

- [ ] Implement `pkg/store/store.go` — define storage interface:
  ```go
  type Store interface {
      PutKey(ctx context.Context, kid string, jwk []byte) error
      GetKey(ctx context.Context, kid string) ([]byte, error)
      DeleteKey(ctx context.Context, kid string) error
      ListKeys(ctx context.Context) ([]string, error)
      PutJWKS(ctx context.Context, data []byte) error
      GetJWKS(ctx context.Context) ([]byte, error)
      PutDiscovery(ctx context.Context, data []byte) error
      GeneratePresignedPutURL(ctx context.Context, kid string, ttl time.Duration) (string, error)
  }
  ```
- [ ] Implement `pkg/store/s3.go` — S3-backed store using `aws-sdk-go-v2`
- [ ] Implement `pkg/store/memory.go` — in-memory store for local dev/testing
- [ ] Implement `pkg/registry/registry.go` — core registry logic:
  - `Register(kid string, jwk json.RawMessage) (presignedURL string, err error)`
    - Validates JWK structure
    - Generates S3 pre-signed PUT URL scoped to `keys/{kid}.json`
    - Returns URL to agent
  - `DeleteKey(kid string) error`
    - Removes key from S3
    - Triggers JWKS rebuild
  - `RebuildJWKS() error`
    - Lists all keys in `keys/` prefix
    - Aggregates into JWKS document
    - Runs safety validation (see below)
    - Writes `jwks.json` to S3
- [ ] Implement JWKS safety validation (`pkg/registry/safety.go`):
  - Never publish empty JWKS
  - Max 3 keys removed per operation
  - Max 10% keys removed per operation
  - Minimum key count floor
  - All thresholds configurable
- [ ] Implement `pkg/registry/handler.go` — HTTP handlers:
  - `POST /register` — authenticated, returns pre-signed URL
  - `DELETE /keys/{kid}` — authenticated, removes key
  - `GET /.well-known/openid-configuration` — public, serves discovery doc (can also be served directly from S3)
  - `GET /.well-known/jwks.json` — public, serves JWKS (can also be served directly from S3)
  - `GET /healthz` — health check
- [ ] Implement registry authentication middleware:
  - Stage 1: shared bootstrap token (`Authorization: Bearer <token>`)
  - Token loaded from environment variable or file
- [ ] Implement `cmd/registry/main.go`:
  - Parse flags/env: `--listen-addr`, `--s3-bucket`, `--s3-region`, `--issuer`, `--auth-token-file`
  - Initialize S3 store, registry, HTTP server
  - Graceful shutdown on SIGTERM/SIGINT
- [ ] Write integration tests using in-memory store
- [ ] Create `Dockerfile.registry`

### Deliverables
- Registry starts, accepts `POST /register`, returns pre-signed URL
- Agent can upload JWK to S3 via pre-signed URL
- JWKS is rebuilt after key upload
- OIDC discovery and JWKS endpoints return valid JSON
- Safety validation prevents dangerous JWKS updates

---

## Stage 2: kube-oidc-fed-broker — Key Management & Registration

**Goal**: Implement the agent's startup lifecycle: key generation, persistence in K8s Secrets, and public key registration with the registry.

### Tasks

- [ ] Implement `pkg/agent/keymanager.go` — key lifecycle:
  - `LoadOrGenerateKey(ctx context.Context, client kubernetes.Interface, namespace, secretName string) (*ecdsa.PrivateKey, string, error)`
    - Try to load private key from K8s Secret `kube-oidc-fed-signing-key`
    - If not found, generate new EC P-256 key pair
    - Store private key + `kid` in K8s Secret
    - Return private key and kid
  - Use `k8s.io/client-go` for Secret CRUD:
    - `clientset.CoreV1().Secrets(namespace).Get()`
    - `clientset.CoreV1().Secrets(namespace).Create()`
    - `clientset.CoreV1().Secrets(namespace).Update()`
- [ ] Implement `pkg/agent/registrar.go` — registry communication:
  - `RegisterKey(ctx context.Context, registryURL, authToken, kid string, jwk []byte) error`
    - POST to `{registryURL}/register` with `{ "kid": "...", "jwk": {...} }`
    - Receive pre-signed URL
    - PUT JWK JSON to pre-signed URL
    - Retry with exponential backoff
- [ ] Implement `pkg/agent/agent.go` — agent orchestration:
  - Initialize Kubernetes clientset (in-cluster config via `rest.InClusterConfig()`)
  - Call `LoadOrGenerateKey` → call `RegisterKey`
  - Start HTTP server for token exchange (placeholder endpoint for now)
- [ ] Implement `cmd/agent/main.go`:
  - Parse flags/env: `--issuer`, `--registry`, `--audience`, `--token-ttl`, `--cluster-id`, `--namespace`, `--auth-token-file`
  - Initialize agent, start server
  - Graceful shutdown
- [ ] RBAC manifests (`deploy/agent/`):
  - ServiceAccount `kube-oidc-fed-broker`
  - Role: `get`, `create`, `update` on Secrets in `kube-oidc-fed-system`
  - Role: `create` on `tokenreviews` (authentication.k8s.io/v1)
  - RoleBinding + ClusterRoleBinding
- [ ] Write unit tests with fake K8s clientset (`k8s.io/client-go/kubernetes/fake`)
- [ ] Create `Dockerfile.agent`

### Deliverables
- Agent generates key pair on first start, persists in K8s Secret
- Agent loads existing key on restart (no new registration)
- Agent registers public key with registry via pre-signed URL flow
- RBAC manifests allow agent to manage its Secret and perform TokenReview

---

## Stage 3: kube-oidc-fed-broker — Token Exchange Endpoint

**Goal**: Implement the runtime token exchange: pods present K8s SA tokens, agent validates and returns signed federated JWTs.

### Tasks

- [ ] Implement `pkg/agent/tokenreview.go`:
  - `ValidateToken(ctx context.Context, client kubernetes.Interface, token string, audience string) (*TokenInfo, error)`
    - Create `TokenReview` via `clientset.AuthenticationV1().TokenReviews().Create()`
    - Extract namespace, service account name from response
    - Return `TokenInfo{ Namespace, ServiceAccount, UID }`
- [ ] Implement `pkg/agent/handler.go` — HTTP handler for token exchange:
  - `POST /token/exchange`
    - Request body: `{ "token": "<k8s-sa-token>" }` or token in `Authorization` header
    - Validate K8s SA token via TokenReview
    - Construct JWT claims:
      - `iss` = configured issuer
      - `sub` = `system:serviceaccount:{namespace}:{sa_name}`
      - `aud` = configured audience (e.g., `sts.amazonaws.com`)
      - `cluster_id` = configured cluster ID
      - `exp` = now + configured TTL
      - `iat` = now
      - `nbf` = now
    - Sign JWT with agent's private key (ES256, kid in header)
    - Return `{ "token": "<signed-jwt>", "expires_at": <unix_ts> }`
  - `GET /healthz` — health check
  - `GET /readyz` — ready check (key loaded + registered)
- [ ] Rate limiting / basic request validation
- [ ] Implement token exchange client SDK (optional, for pod-side convenience):
  - `pkg/client/client.go` — simple HTTP client that reads the projected SA token from the default path, calls the agent, and returns the federated JWT
- [ ] Write unit tests with mock TokenReview responses
- [ ] Write integration test: generate key → sign JWT → verify JWT with public key

### Deliverables
- Pods can call agent's `/token/exchange` endpoint with their K8s SA token
- Agent validates the token, signs a federated JWT, and returns it
- Returned JWT has correct claims structure matching the spec
- JWT is verifiable using the JWK in the registry's JWKS

---

## Stage 4: Key Rotation

**Goal**: Implement graceful key rotation with zero-downtime for token verification.

### Tasks

- [ ] Implement `pkg/agent/rotation.go`:
  - `RotateKey(ctx context.Context) error`
    - Generate new key pair, derive new kid
    - Register new public key with registry (old key still active in JWKS)
    - Store new key alongside old key in K8s Secret:
      ```yaml
      data:
        private-key.pem: <new-key>
        kid: <new-kid>
        prev-private-key.pem: <old-key>
        prev-kid: <old-kid>
        rotation-started-at: <timestamp>
      ```
    - After configurable grace period (default: 24h), switch to signing with new key
    - After switching, call `DELETE /keys/{old_kid}` on registry
    - Remove old key from Secret
  - Rotation trigger options:
    - Periodic (configurable interval, e.g., 90 days)
    - Manual (HTTP endpoint `POST /admin/rotate` or signal)
- [ ] Implement rotation state machine:
  ```
  STABLE → DUAL_KEY (new registered, old signing)
         → SWITCHED (new signing, old still in JWKS)
         → CLEANUP (old removed from JWKS)
         → STABLE
  ```
- [ ] Agent flags:
  - `--rotation-interval` (default: `0` = disabled)
  - `--rotation-grace-period` (default: `24h`)
- [ ] Write tests for full rotation lifecycle
- [ ] Write tests for crash recovery mid-rotation (agent restarts, resumes from state in Secret)

### Deliverables
- Agent can rotate keys with zero-downtime
- Old key remains in JWKS during grace period
- Rotation state persisted in K8s Secret (crash-safe)
- Manual and automatic rotation triggers

---

## Stage 5: Deployment, Observability & Hardening

**Goal**: Production-ready deployment artifacts, metrics, logging, and security hardening.

### Tasks

- [ ] Kubernetes manifests (`deploy/agent/`):
  - Deployment (2 replicas, leader election for rotation)
  - Service (ClusterIP, port 8443)
  - NetworkPolicy (restrict ingress to workload pods only)
  - PodDisruptionBudget
  - ServiceAccount + RBAC
  - ConfigMap for agent configuration
- [ ] Kubernetes manifests (`deploy/registry/`):
  - Deployment
  - Service / Ingress
  - IAM annotations for S3 access (IRSA or equivalent)
- [ ] TLS for agent server:
  - Serve on HTTPS using cert from K8s Secret or cert-manager
  - Or use a sidecar / service mesh for mTLS
- [ ] Structured logging (using `slog` or `logr`):
  - Key lifecycle events: generated, loaded, registered, rotated
  - Token exchange events: success, failure (with reason), latency
  - JWKS rebuild events: success, failure, key count
- [ ] Prometheus metrics:
  - `kube_oidc_fed_broker_token_exchange_total` (counter, labels: status, namespace)
  - `kube_oidc_fed_broker_token_exchange_duration_seconds` (histogram)
  - `kube_oidc_fed_broker_key_age_seconds` (gauge)
  - `kube_oidc_fed_broker_key_rotation_total` (counter, labels: status)
  - `kube_oidc_fed_registry_jwks_rebuild_total` (counter, labels: status)
  - `kube_oidc_fed_registry_jwks_key_count` (gauge)
  - `kube_oidc_fed_registry_key_registration_total` (counter, labels: status)
- [ ] Leader election for agent (using `k8s.io/client-go/tools/leaderelection`):
  - Only the leader performs key registration and rotation
  - All replicas serve token exchange
- [ ] Health and readiness probes:
  - `/healthz` — process is alive
  - `/readyz` — key is loaded and registered
- [ ] Security hardening:
  - Run as non-root, read-only root filesystem
  - Drop all capabilities
  - Seccomp profile
  - Resource limits
- [ ] Write E2E test:
  - Deploy agent + registry in kind/minikube
  - Create workload pod with ServiceAccount
  - Pod calls agent, receives JWT
  - Verify JWT against JWKS endpoint
  - (Optional) Verify JWT against AWS STS in a sandbox account

### Deliverables
- Production-grade deployment manifests
- Full observability stack (logs, metrics, health checks)
- Leader election prevents split-brain key management
- Security-hardened containers
- E2E test proving the full flow works

---

## Stage 6: Helm Charts & CI/CD

**Goal**: Package for distribution and automate build/test/release.

### Tasks

- [ ] Helm chart for agent (`charts/kube-oidc-fed-broker/`):
  - Parameterized: issuer, registry URL, audience, cluster ID, token TTL, image, replicas
  - RBAC, ServiceAccount, ConfigMap, Secret references
  - Optional: PDB, NetworkPolicy, monitoring ServiceMonitor
- [ ] Helm chart for registry (`charts/kube-oidc-fed-registry/`):
  - Parameterized: S3 bucket, region, issuer domain, auth config, safety thresholds
  - Optional: Ingress, TLS, CloudFront invalidation config
- [ ] GitHub Actions CI pipeline:
  - Lint (`golangci-lint`)
  - Unit tests
  - Integration tests
  - Build Docker images
  - Trivy / vulnerability scanning
  - Helm chart linting
- [ ] GitHub Actions release pipeline:
  - Tag-triggered
  - Build + push multi-arch Docker images to GHCR
  - Publish Helm charts to GitHub Pages or OCI registry
- [ ] Documentation:
  - Quick start guide
  - Architecture deep-dive
  - Operations runbook (rotation, cluster onboarding, incident response)
  - API reference

### Deliverables
- Helm charts for both components
- Automated CI/CD pipeline
- Published container images and Helm charts
- Comprehensive documentation

---

## Dependency Summary

```
Stage 0 (Crypto & Scaffolding)
    │
    ├──→ Stage 1 (Registry)
    │        │
    │        └──→ Stage 2 (Agent Key Mgmt) ──→ Stage 3 (Token Exchange)
    │                                                │
    │                                                └──→ Stage 4 (Key Rotation)
    │                                                          │
    └──────────────────────────────────────────────────────────→ Stage 5 (Deploy & Observability)
                                                                      │
                                                                      └──→ Stage 6 (Helm & CI/CD)
```

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go | Native K8s ecosystem, strong crypto stdlib, single binary |
| Key algorithm | EC P-256 (ES256) | Compact signatures, widely supported by AWS/GCP OIDC |
| KID derivation | `sha256(DER pubkey)[:16]` hex | Deterministic, no coordination needed |
| K8s client | `client-go` | Official, stable, supports in-cluster auth |
| JWT library | `golang-jwt/jwt/v5` | Most popular, well-maintained, supports custom headers |
| JWK library | `go-jose/go-jose/v4` | Battle-tested JOSE implementation |
| Storage | Interface + S3 impl | Testable with in-memory store, production with S3 |
| Registry auth (initial) | Shared token | Simplest. Can upgrade to mTLS later |
| Agent HA | Leader election for mutations, all replicas for reads | Standard K8s pattern |

## Estimated Timeline

| Stage | Effort | Depends On |
|---|---|---|
| Stage 0: Scaffolding & Crypto | 2-3 days | — |
| Stage 1: Registry Core | 3-4 days | Stage 0 |
| Stage 2: Agent Key Mgmt | 3-4 days | Stage 0, 1 |
| Stage 3: Token Exchange | 2-3 days | Stage 2 |
| Stage 4: Key Rotation | 2-3 days | Stage 3 |
| Stage 5: Deploy & Observability | 3-5 days | Stage 4 |
| Stage 6: Helm & CI/CD | 2-3 days | Stage 5 |
| **Total** | **~17-25 days** | |