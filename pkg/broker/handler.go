package broker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/hixichen/kube-oidc-fed/pkg/config"
	kidcrypto "github.com/hixichen/kube-oidc-fed/pkg/crypto"
	"github.com/hixichen/kube-oidc-fed/pkg/jwks"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type BrokerHandler struct {
	client kubernetes.Interface
	mu     sync.RWMutex
	key    *ecdsa.PrivateKey
	kid    string
	cfg    *config.BrokerConfig
	logger *zap.Logger
}

func NewBrokerHandler(client kubernetes.Interface, key *ecdsa.PrivateKey, kid string, cfg *config.BrokerConfig, logger *zap.Logger) http.Handler {
	h := &BrokerHandler{
		client: client,
		key:    key,
		kid:    kid,
		cfg:    cfg,
		logger: logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token/exchange", h.handleTokenExchange)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
	mux.HandleFunc("POST /admin/rotate", h.authMiddleware(h.handleRotate))
	return mux
}

func (h *BrokerHandler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" || token != h.cfg.AuthToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type tokenExchangeRequest struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type tokenExchangeResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type subjectTemplateData struct {
	Namespace      string
	ServiceAccount string
}

func (h *BrokerHandler) buildSubject(info *TokenInfo) string {
	tmplStr := h.cfg.JWTSubjectTemplate
	if tmplStr == "" {
		tmplStr = "system:serviceaccount:{{.Namespace}}:{{.ServiceAccount}}"
	}
	tmpl, err := template.New("subject").Parse(tmplStr)
	if err != nil {
		return fmt.Sprintf("system:serviceaccount:%s:%s", info.Namespace, info.ServiceAccount)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, subjectTemplateData{Namespace: info.Namespace, ServiceAccount: info.ServiceAccount}); err != nil {
		return fmt.Sprintf("system:serviceaccount:%s:%s", info.Namespace, info.ServiceAccount)
	}
	return buf.String()
}

func (h *BrokerHandler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	var req tokenExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	audiences := req.Audiences
	if len(audiences) == 0 {
		audiences = h.cfg.Audience
	}
	info, err := ValidateToken(r.Context(), h.client, req.Token, audiences)
	if err != nil {
		h.logger.Warn("token validation failed", zap.Error(err))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	exp := now.Add(h.cfg.TokenTTL)

	var extra map[string]interface{}
	if len(h.cfg.JWTExtraClaims) > 0 {
		extra = make(map[string]interface{}, len(h.cfg.JWTExtraClaims))
		for k, v := range h.cfg.JWTExtraClaims {
			extra[k] = v
		}
	}

	h.mu.RLock()
	key := h.key
	kid := h.kid
	h.mu.RUnlock()

	claims := kidcrypto.Claims{
		Issuer:    h.cfg.Issuer,
		Subject:   h.buildSubject(info),
		Audience:  audiences,
		ClusterID: h.cfg.ClusterID,
		ExpiresAt: exp,
		IssuedAt:  now,
		NotBefore: now,
		Extra:     extra,
	}
	token, err := kidcrypto.SignToken(key, kid, claims)
	if err != nil {
		h.logger.Error("sign token failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenExchangeResponse{Token: token, ExpiresAt: exp.Unix()})
}

func (h *BrokerHandler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (h *BrokerHandler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	ready := h.key != nil
	h.mu.RUnlock()
	if !ready {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

type rotateResponse struct {
	KID string `json:"kid"`
}

func (h *BrokerHandler) handleRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.mu.RLock()
	currentKID := h.kid
	h.mu.RUnlock()

	newPresignedURL, err := ReissuePresignedURL(ctx, h.cfg.RegistryURL, h.cfg.AuthToken, currentKID, h.logger)
	if err != nil {
		h.logger.Error("reissue presigned URL failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newKey, err := kidcrypto.GenerateKeyPair()
	if err != nil {
		h.logger.Error("generate key pair failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newKID, err := kidcrypto.DeriveKID(&newKey.PublicKey)
	if err != nil {
		h.logger.Error("derive kid failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newJWKObj, err := jwks.PublicKeyToJWK(&newKey.PublicKey, newKID)
	if err != nil {
		h.logger.Error("build jwk failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newJWKBytes, err := json.Marshal(newJWKObj)
	if err != nil {
		h.logger.Error("marshal jwk failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, err := RegisterKey(ctx, h.cfg.RegistryURL, h.cfg.AuthToken, newKID, newJWKBytes, h.logger); err != nil {
		h.logger.Error("register new key failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := uploadToURL(ctx, newPresignedURL, newJWKBytes); err != nil {
		h.logger.Warn("upload to presigned URL failed", zap.Error(err))
	}

	if err := StoreRotatedKey(ctx, h.client, h.cfg.Namespace, h.cfg.SecretName, newKey, newKID); err != nil {
		h.logger.Error("store rotated key failed", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	h.key = newKey
	h.kid = newKID
	h.mu.Unlock()

	h.logger.Info("rotation complete", zap.String("kid", newKID))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rotateResponse{KID: newKID})
}

func uploadToURL(ctx context.Context, url string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload returned %d", resp.StatusCode)
	}
	return nil
}
