package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hixichen/kube-kidring/pkg/jwks"
	"github.com/hixichen/kube-kidring/pkg/oidc"
	"github.com/hixichen/kube-kidring/pkg/store"
)

type Registry struct {
	store  store.Store
	issuer string
	logger *slog.Logger
	safety SafetyConfig
}

func New(st store.Store, issuer string, logger *slog.Logger, safety SafetyConfig) *Registry {
	return &Registry{store: st, issuer: issuer, logger: logger, safety: safety}
}

func (r *Registry) Initialize(ctx context.Context) error {
	doc := oidc.NewDiscoveryDocument(r.issuer)
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal discovery: %w", err)
	}
	if err := r.store.PutDiscovery(ctx, data); err != nil {
		return fmt.Errorf("put discovery: %w", err)
	}
	// Init JWKS if empty
	existing, _ := r.store.GetJWKS(ctx)
	if len(existing) == 0 {
		empty := &jwks.JWKS{Keys: []jwks.JWK{}}
		jwksData, _ := json.Marshal(empty)
		if err := r.store.PutJWKS(ctx, jwksData); err != nil {
			return fmt.Errorf("init jwks: %w", err)
		}
	}
	return nil
}

func (r *Registry) Register(ctx context.Context, kid string, jwkData json.RawMessage) (string, error) {
	url, err := r.store.GeneratePresignedPutURL(ctx, kid, 15*time.Minute)
	if err != nil {
		return "", fmt.Errorf("generate presigned URL: %w", err)
	}
	r.logger.Info("registered key", "kid", kid)
	return url, nil
}

func (r *Registry) StoreKey(ctx context.Context, kid string, jwkData []byte) error {
	if err := r.store.PutKey(ctx, kid, jwkData); err != nil {
		return fmt.Errorf("store key: %w", err)
	}
	return r.RebuildJWKS(ctx)
}

func (r *Registry) DeleteKey(ctx context.Context, kid string) error {
	existing, err := r.store.GetJWKS(ctx)
	var beforeCount int
	if err == nil && len(existing) > 0 {
		var j jwks.JWKS
		if err := json.Unmarshal(existing, &j); err == nil {
			beforeCount = len(j.Keys)
		}
	}
	// Fetch key before deletion so we can restore it if safety check fails
	keyBackup, _ := r.store.GetKey(ctx, kid)
	if err := r.store.DeleteKey(ctx, kid); err != nil {
		return fmt.Errorf("delete key: %w", err)
	}
	kids, err := r.store.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	afterCount := len(kids)
	if err := ValidateJWKSDelta(beforeCount, afterCount, r.safety); err != nil {
		// Restore key using the backup fetched before deletion
		if len(keyBackup) > 0 {
			_ = r.store.PutKey(ctx, kid, keyBackup)
		}
		return fmt.Errorf("safety check: %w", err)
	}
	return r.RebuildJWKS(ctx)
}

func (r *Registry) RebuildJWKS(ctx context.Context) error {
	kids, err := r.store.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	var keys []jwks.JWK
	for _, kid := range kids {
		data, err := r.store.GetKey(ctx, kid)
		if err != nil {
			r.logger.Warn("failed to get key", "kid", kid, "err", err)
			continue
		}
		var jwk jwks.JWK
		if err := json.Unmarshal(data, &jwk); err != nil {
			r.logger.Warn("failed to unmarshal jwk", "kid", kid, "err", err)
			continue
		}
		keys = append(keys, jwk)
	}
	j := &jwks.JWKS{Keys: keys}
	if j.Keys == nil {
		j.Keys = []jwks.JWK{}
	}
	data, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("marshal jwks: %w", err)
	}
	return r.store.PutJWKS(ctx, data)
}
