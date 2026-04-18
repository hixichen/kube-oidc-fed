package broker

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hixichen/kube-oidc-fed/pkg/config"
	"github.com/hixichen/kube-oidc-fed/pkg/jwks"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type Broker struct {
	cfg          *config.BrokerConfig
	client       kubernetes.Interface
	key          *ecdsa.PrivateKey
	kid          string
	presignedURL string
	logger       *zap.Logger
}

func NewBroker(cfg *config.BrokerConfig, client kubernetes.Interface, logger *zap.Logger) *Broker {
	return &Broker{cfg: cfg, client: client, logger: logger}
}

func (b *Broker) Initialize(ctx context.Context) error {
	key, kid, err := LoadOrGenerateKey(ctx, b.client, b.cfg.Namespace, b.cfg.SecretName)
	if err != nil {
		return fmt.Errorf("load or generate key: %w", err)
	}
	b.key = key
	b.kid = kid

	jwk, err := jwks.PublicKeyToJWK(&key.PublicKey, kid)
	if err != nil {
		return fmt.Errorf("build jwk: %w", err)
	}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("marshal jwk: %w", err)
	}
	presignedURL, err := RegisterKey(ctx, b.cfg.RegistryURL, b.cfg.AuthToken, kid, jwkJSON, b.logger)
	if err != nil {
		return fmt.Errorf("register key: %w", err)
	}
	b.presignedURL = presignedURL

	if err := StorePresignedURL(ctx, b.client, b.cfg.Namespace, b.cfg.SecretName, presignedURL); err != nil {
		b.logger.Warn("failed to store presigned URL in secret", zap.Error(err))
	}

	b.logger.Info("broker initialized", zap.String("kid", kid))
	return nil
}

func (b *Broker) HTTPHandler() http.Handler {
	return NewBrokerHandler(b.client, b.key, b.kid, b.cfg, b.logger)
}
