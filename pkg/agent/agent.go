package agent

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/hixichen/kube-kidring/pkg/config"
	"github.com/hixichen/kube-kidring/pkg/jwks"
	"k8s.io/client-go/kubernetes"
)

type Agent struct {
	cfg    *config.AgentConfig
	client kubernetes.Interface
	key    *ecdsa.PrivateKey
	kid    string
	logger *slog.Logger
}

func NewAgent(cfg *config.AgentConfig, client kubernetes.Interface, logger *slog.Logger) *Agent {
	return &Agent{cfg: cfg, client: client, logger: logger}
}

func (a *Agent) Initialize(ctx context.Context) error {
	key, kid, err := LoadOrGenerateKey(ctx, a.client, a.cfg.Namespace, a.cfg.SecretName)
	if err != nil {
		return fmt.Errorf("load or generate key: %w", err)
	}
	a.key = key
	a.kid = kid

	jwk, err := jwks.PublicKeyToJWK(&key.PublicKey, kid)
	if err != nil {
		return fmt.Errorf("build jwk: %w", err)
	}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("marshal jwk: %w", err)
	}
	if err := RegisterKey(ctx, a.cfg.RegistryURL, a.cfg.AuthToken, kid, jwkJSON); err != nil {
		return fmt.Errorf("register key: %w", err)
	}
	a.logger.Info("agent initialized", "kid", kid)
	return nil
}

func (a *Agent) HTTPHandler() http.Handler {
	return NewAgentHandler(a.client, a.key, a.kid, a.cfg.Issuer, a.cfg.Audience, a.cfg.ClusterID, a.cfg.TokenTTL, a.logger)
}
