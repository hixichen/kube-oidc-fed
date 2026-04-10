# kube-kidring: Federated Workload Identity Token Exchange

## TL;DR

kube-kidring enables pods on any number of Kubernetes clusters to obtain cloud provider credentials (AWS/GCP) via a single OIDC identity provider — without per-cluster OIDC registration. It has two components:

1. **Agent** (per-cluster): Generates a cluster-unique signing key pair, uploads the public key to the registry, validates local K8s ServiceAccount tokens, and signs federated JWTs.
2. **Registry** (central, S3-backed): Accepts public key uploads via pre-signed URLs, builds and serves the JWKS and OIDC discovery endpoints that AWS/GCP consume for federation.

Each cluster signs with its own private key (blast radius isolation). All clusters share one OIDC issuer. `kid = sha256(public_key_der)[0:16]`.

---

## Problem

Organizations running many Kubernetes clusters across multiple infrastructure providers face a common challenge: workloads need cloud provider credentials via standard OIDC federation, but pods can be scheduled on any cluster.

The naive approaches don't work:

- **One OIDC provider per cluster in AWS/GCP**: Every IAM role trust policy needs N entries (one per cluster). Adding a cluster means updating every role. Operationally unmaintainable at scale.
- **One shared signing key across all clusters**: If any single cluster is compromised, the attacker can forge tokens for every workload on every cluster. Unacceptable blast radius.
- **Central token exchange service (runtime call)**: Adds latency to every pod cold start, introduces a cross-network dependency, and creates a single point of failure for all cloud access.

We cannot assume uniform OIDC issuer configuration across clusters — each cluster may be managed differently and restarting API servers to reconfigure `--service-account-issuer` is not feasible.

---

## Design Goals

- Adding a new cluster should not require touching any AWS/GCP IAM configuration.
- A compromised cluster should not be able to impersonate workloads on other clusters.
- No runtime dependency on a central service for token signing.
- Minimal infrastructure requirements — S3 bucket and a deployment, not a full PKI stack.

---

## Architecture Overview

```
                    ┌──────────────────────────────────────┐
                    │         kube-kidring Registry         │
                    │     (Deployment, outside clusters)    │
                    │                                      │
                    │  ┌────────────────────────────────┐  │
                    │  │  S3 Bucket (versioned)         │  │
                    │  │  ├── jwks.json                 │  │
                    │  │  ├── openid-configuration      │  │
                    │  │  └── keys/                     │  │
                    │  │      ├── a3f8b2c1e9d04f17.json │  │
                    │  │      ├── 7b2e9a0fc3d81e52.json │  │
                    │  │      └── ...                   │  │
                    │  └────────────────────────────────┘  │
                    │                                      │
                    │  API:                                 │
                    │  POST /register  → pre-signed URL    │
                    │  GET  /.well-known/openid-config...  │
                    │  GET  /.well-known/jwks.json         │
                    └──────────┬──────────────┬────────────┘
                               │              │
                   upload pub key        AWS/GCP fetches
                   (pre-signed URL)      JWKS for verification
                               │              │
          ┌────────────────────┼──────────────┼────────────────────┐
          │                    │              │                    │
┌─────────┴────────┐ ┌────────┴─────────┐ ┌─┴────────────────┐   │
│ Workload Cluster  │ │ Workload Cluster │ │ Workload Cluster │  ...
│ (Provider A)      │ │ (Provider B)     │ │ (Provider C)     │
│                   │ │                  │ │                  │
│ ┌───────────────┐ │ │ ┌──────────────┐ │ │ ┌──────────────┐ │
│ │ kidring-agent │ │ │ │ kidring-agent│ │ │ │ kidring-agent│ │
│ │               │ │ │ │              │ │ │ │              │ │
│ │ - generates   │ │ │ │ - generates  │ │ │ │ - generates  │ │
│ │   key pair    │ │ │ │   key pair   │ │ │ │   key pair   │ │
│ │ - uploads pub │ │ │ │ - uploads pub│ │ │ │ - uploads pub│ │
│ │ - signs JWTs  │ │ │ │ - signs JWTs │ │ │ │ - signs JWTs │ │
│ │ kid=a3f8...   │ │ │ │ kid=7b2e...  │ │ │ │ kid=c91d...  │ │
│ └───────┬───────┘ │ │ └──────┬───────┘ │ │ └──────┬───────┘ │
│         │         │ │        │         │ │        │         │
│ ┌───────┴───────┐ │ │ ┌──────┴───────┐ │ │ ┌──────┴───────┐ │
│ │ Workload Pod  │ │ │ │ Workload Pod │ │ │ │ Workload Pod │ │
│ └───────────────┘ │ │ └──────────────┘ │ │ └──────────────┘ │
└───────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## Component 1: kidring-agent (In-Cluster)

Runs as a Deployment in each workload cluster. Responsible for key generation, public key registration, and local JWT signing.

### Lifecycle

```
Startup:
  1. Generate EC P-256 key pair (or load existing from K8s Secret)
  2. Compute kid = sha256(public_key_der)[0:16]
  3. Call registry: POST /register
     → receives S3 pre-signed PUT URL
  4. Upload public key (JWK JSON) to pre-signed URL
  5. Start serving token exchange endpoint (ClusterIP)

Runtime (token exchange):
  1. Pod presents K8s ServiceAccount token
  2. Agent validates via local TokenReview API
  3. Agent extracts namespace, service account name
  4. Agent signs JWT:
     header: { alg: ES256, kid: <fingerprint> }
     payload: {
       iss: https://token.example.com,
       sub: system:serviceaccount:{namespace}:{sa_name},
       aud: sts.amazonaws.com,
       cluster_id: <cluster-identifier>,
       exp: <now + TTL>
     }
  5. Returns JWT to pod
  6. Pod calls AWS STS AssumeRoleWithWebIdentity directly

Key Persistence:
  Agent stores its private key in a K8s Secret in its own namespace.
  On restart, it loads the existing key rather than generating a new one.
  New key generation only happens on first deploy or explicit rotation.
```

### Key Rotation (Agent-Initiated)

```
1. Agent generates new key pair
2. Compute new_kid = sha256(new_public_key_der)[0:16]
3. POST /register → upload new public key
   (old key still in JWKS, old kid still valid)
4. Agent waits for configurable grace period (default: 24h)
   to allow AWS/GCP JWKS cache to pick up new key
5. Agent switches to signing with new key
6. Agent calls DELETE /keys/{old_kid} on registry
   (or: registry auto-expires keys not refreshed within TTL)
7. Agent deletes old key from K8s Secret
```

### Agent Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kidring-agent
  namespace: kidring-system
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: agent
        image: ghcr.io/org/kube-kidring-agent:latest
        args:
          - --issuer=https://token.example.com
          - --registry=https://registry.example.com
          - --audience=sts.amazonaws.com
          - --token-ttl=15m
          - --cluster-id=$(CLUSTER_ID)
        env:
          - name: CLUSTER_ID
            valueFrom:
              configMapKeyRef:
                name: kidring-config
                key: cluster-id
```

---

## Component 2: kidring-registry (Outside Clusters)

A lightweight service backed by S3. Two responsibilities: accept public key uploads from agents, and serve OIDC discovery + JWKS endpoints for cloud providers.

### API

```
POST   /register
  Auth: shared secret or mTLS (agent → registry)
  Body: { "kid": "a3f8...", "jwk": { ... } }
  Response: { "upload_url": "<S3 pre-signed PUT URL>" }

  The agent then PUTs the JWK JSON directly to S3 via the pre-signed URL.
  Registry does NOT proxy the key material — agent uploads directly to S3.

DELETE /keys/{kid}
  Auth: shared secret or mTLS
  Removes a key from the registry.
  Subject to safety checks (see JWKS Safety below).

GET    /.well-known/openid-configuration
  Public. No auth.
  Returns static OIDC discovery document.
  Served directly from S3 / CDN.

GET    /.well-known/jwks.json
  Public. No auth.
  Returns aggregated JWKS with all registered cluster public keys.
  Served directly from S3 / CDN.
```

### S3 Bucket Layout

```
s3://kidring-registry/
  ├── .well-known/
  │   ├── openid-configuration        # static OIDC discovery JSON
  │   └── jwks.json                   # aggregated JWKS (rebuilt on key changes)
  └── keys/
      ├── a3f8b2c1e9d04f17.json       # individual JWK for cluster A
      ├── 7b2e9a0fc3d81e52.json       # individual JWK for cluster B
      └── ...
```

### JWKS Build Pipeline

When a key is added or removed, the registry rebuilds `jwks.json`:

```
1. List all objects under s3://kidring-registry/keys/
2. Read each JWK JSON
3. Aggregate into JWKS: { "keys": [ ...all JWKs... ] }
4. Run safety validation (see below)
5. Write jwks.json to S3
6. CloudFront invalidation (optional, or rely on short TTL)
```

This is a write-time operation, not read-time. The JWKS is a static S3 object served to AWS/GCP on demand.

### OIDC Discovery Document

```json
{
  "issuer": "https://token.example.com",
  "jwks_uri": "https://token.example.com/.well-known/jwks.json",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

### Registry Authentication

The registry needs to authenticate agents to prevent unauthorized key registration. Options (in order of preference):

1. **Shared bootstrap token**: Agent deployed with a registration token (K8s Secret). Simple. Sufficient for most deployments.
2. **mTLS**: Agent presents a client certificate. Stronger, but requires cert distribution.
3. **K8s SA token verification**: Agent sends its own K8s SA token; registry validates it against the cluster's OIDC discovery. Chicken-and-egg problem for the first registration, but works for subsequent operations.

---

## Token Exchange Flow (End to End)

```
┌──────────┐    ┌──────────────┐    ┌───────────┐    ┌─────────┐
│ Workload │    │ kidring-agent│    │  AWS STS  │    │ AWS S3  │
│ Pod      │    │ (in-cluster) │    │           │    │ (target)│
└────┬─────┘    └──────┬───────┘    └─────┬─────┘    └────┬────┘
     │                 │                  │               │
     │ 1. K8s SA token │                  │               │
     │────────────────>│                  │               │
     │                 │                  │               │
     │                 │ 2. TokenReview   │               │
     │                 │    (local API)   │               │
     │                 │                  │               │
     │ 3. Signed JWT   │                  │               │
     │<────────────────│                  │               │
     │                 │                  │               │
     │ 4. AssumeRoleWithWebIdentity       │               │
     │───────────────────────────────────>│               │
     │                 │                  │               │
     │                 │    5. AWS fetches JWKS from       │
     │                 │    token.example.com (S3/CDN)     │
     │                 │    matches kid → verifies sig     │
     │                 │                  │               │
     │ 6. Temporary AWS credentials       │               │
     │<───────────────────────────────────│               │
     │                 │                  │               │
     │ 7. Access S3    │                  │               │
     │────────────────────────────────────────────────────>│
     │                 │                  │               │
```

---

## AWS IAM Configuration

One-time setup per AWS account. Adding/removing clusters requires zero AWS changes.

### OIDC Provider (one per AWS account)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.example.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list <certificate-thumbprint>
```

### IAM Role Trust Policy (per workload role)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.example.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.example.com:aud": "sts.amazonaws.com",
        "token.example.com:sub": "system:serviceaccount:my-namespace:my-sa"
      }
    }
  }]
}
```

Adding cluster 81 or cluster 200 changes nothing here.

---

## JWT Structure

```json
{
  "header": {
    "alg": "ES256",
    "typ": "JWT",
    "kid": "a3f8b2c1e9d04f17"
  },
  "payload": {
    "iss": "https://token.example.com",
    "sub": "system:serviceaccount:my-namespace:my-sa",
    "aud": "sts.amazonaws.com",
    "exp": 1234567890,
    "iat": 1234564290,
    "nbf": 1234564290,
    "cluster_id": "us-east-cluster-07"
  }
}
```

### `kid` Derivation

```python
import hashlib
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def derive_kid(public_key) -> str:
    der_bytes = public_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der_bytes).hexdigest()[:16]
```

The `kid` is deterministically derived from key material. No naming convention needed. New key = new fingerprint = new `kid`.

---

## JWKS Safety (Preventing Accidental Mass Deletion)

The JWKS is a critical trust document. A bad publish breaks cloud access for all clusters instantly.

### Validation Gate (Pre-Publish)

The registry enforces the following before writing a new `jwks.json`:

```python
new_keys = list_keys_from_s3()
current_jwks = fetch_current_jwks()

current_kids = {k["kid"] for k in current_jwks["keys"]}
new_kids = {k["kid"] for k in new_keys}
removed = current_kids - new_kids

# Rule 1: Never publish empty JWKS
assert len(new_keys) > 0, "Refusing to publish empty JWKS"

# Rule 2: Never remove more than 3 keys in one operation
assert len(removed) <= 3, f"Refusing to remove {len(removed)} keys at once"

# Rule 3: Never remove more than 10% of keys at once
assert len(removed) <= len(current_kids) * 0.10, "Refusing bulk removal"

# Rule 4: Floor check
assert len(new_keys) >= MINIMUM_EXPECTED_CLUSTERS, "Below minimum key count"
```

### S3 Protections

- **Versioning enabled**: Every `jwks.json` write creates a new version. Rollback is instant.
- **MFA-delete enabled**: Prevents accidental or malicious deletion of the bucket or objects.
- **Separate IAM policy**: The registry service role can `PutObject` but cannot `DeleteBucket` or disable versioning.

### Operation Separation

- **Add key**: Automated. Agent calls registry, uploads key, JWKS rebuilt. Low risk.
- **Remove key**: Guarded. Subject to validation checks. Optionally requires manual approval for bulk operations.

### Monitoring

- Alert if JWKS key count drops below expected cluster count.
- Alert if `jwks.json` is not accessible (HTTP non-200).
- Alert if a key is removed outside of a rotation or decommission workflow.
- Dashboard: key count over time, last registration timestamp per cluster.

---

## Blast Radius Analysis

| Scenario | Impact | Mitigation |
|---|---|---|
| Single cluster compromised | Attacker has that cluster's private key. Can forge JWTs with any `sub` claim using that `kid`. | Remove `kid` from registry immediately. Propagation depends on AWS/GCP JWKS cache TTL. |
| Registry S3 bucket down | AWS/GCP cannot fetch new JWKS. Existing cached JWKS continues working. | S3 + CloudFront = highly available. AWS caches JWKS aggressively. |
| Registry service compromised | Attacker could register rogue public keys. | Registration requires auth. S3 validation gate prevents overwriting existing keys without removal approval. |
| JWKS accidentally emptied | All cloud access fails. | Validation gate prevents this. S3 versioning enables instant rollback. |

### Known Limitation: Cross-Cluster Impersonation

If cluster-3 is compromised, the attacker can sign JWTs with any `sub` claim (any namespace, any service account) — not just workloads actually running on cluster-3. AWS validates `iss` and `sub` but does not know which cluster signed the token.

**Possible mitigation**: Use the `cluster_id` custom claim with AWS IAM condition keys to restrict which clusters can assume which roles. This requires maintaining a namespace-to-cluster mapping, which may not be practical with dynamic scheduling.

---

## Out of Scope

- Customer-facing BYOK identity federation (customers bringing their own OIDC provider)
- Token exchange for non-cloud-provider use cases (internal service-to-service auth)
- Changes to K8s API server configuration (`--service-account-issuer`)
- GCP Workload Identity Federation specifics (same pattern, different registration API)

---

## Open Questions

1. **Registry auth model**: Shared bootstrap token is simplest. mTLS is strongest. Which fits the deployment model?

2. **Key expiry**: Should the registry auto-expire keys that haven't been refreshed within a TTL (e.g., 7 days)? This provides automatic cleanup for decommissioned clusters but adds a heartbeat requirement to agents.

3. **Token TTL**: Recommend 15 minutes. Shorter = less exposure. Longer = fewer exchange calls. Configurable per deployment.

4. **Pre-signed URL scope**: The pre-signed PUT URL should be scoped to `keys/{kid}.json` only (prefix-restricted via `starts-with` condition). Agent cannot write to `jwks.json` or `openid-configuration`.

5. **JWKS rebuild trigger**: Rebuild on every key upload (simple, slightly slower)? Or batch with a short delay (e.g., 5s debounce)?

6. **Revocation speed**: AWS JWKS cache TTL is not publicly documented (observed 5-60 minutes). Investigate whether CloudFront `Cache-Control` headers influence AWS's caching behavior.

---

## Appendix

### JWKS Entry Example

```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "a3f8b2c1e9d04f17",
  "use": "sig",
  "alg": "ES256",
  "x": "base64url-encoded-x-coordinate",
  "y": "base64url-encoded-y-coordinate"
}
```

### S3 Pre-Signed URL Generation (Registry Side)

```python
import boto3

s3 = boto3.client("s3")

def generate_upload_url(kid: str) -> str:
    return s3.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": "kidring-registry",
            "Key": f"keys/{kid}.json",
            "ContentType": "application/json",
        },
        ExpiresIn=300,  # 5 minutes
    )
```

### Agent Key Storage (K8s Secret)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kidring-signing-key
  namespace: kidring-system
type: Opaque
data:
  private-key.pem: <base64-encoded-EC-private-key>
  kid: <base64-encoded-kid-string>
```

### Helm Values (Example)

```yaml
# kidring-agent
agent:
  issuer: "https://token.example.com"
  registry: "https://registry.example.com"
  audience: "sts.amazonaws.com"
  tokenTTL: "15m"
  clusterId: "us-east-cluster-07"
  registrationToken:
    secretName: "kidring-registration-token"

# kidring-registry
registry:
  s3:
    bucket: "kidring-registry"
    region: "us-east-1"
  domain: "token.example.com"
  cloudfront:
    enabled: true
    distributionId: "E1234567890"
  safety:
    minKeyCount: 10
    maxRemovalPerOperation: 3
    maxRemovalPercent: 10
```
