package agent

import (
	"crypto/ecdsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	kidcrypto "github.com/hixichen/kube-kidring/pkg/crypto"
	"k8s.io/client-go/kubernetes"
)

type AgentHandler struct {
	client    kubernetes.Interface
	key       *ecdsa.PrivateKey
	kid       string
	issuer    string
	audience  []string
	clusterID string
	tokenTTL  time.Duration
	logger    *slog.Logger
}

func NewAgentHandler(client kubernetes.Interface, key *ecdsa.PrivateKey, kid, issuer string, audience []string, clusterID string, tokenTTL time.Duration, logger *slog.Logger) http.Handler {
	h := &AgentHandler{
		client:    client,
		key:       key,
		kid:       kid,
		issuer:    issuer,
		audience:  audience,
		clusterID: clusterID,
		tokenTTL:  tokenTTL,
		logger:    logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token/exchange", h.handleTokenExchange)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
	return mux
}

type tokenExchangeRequest struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences"`
}

type tokenExchangeResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func (h *AgentHandler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
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
		audiences = h.audience
	}
	info, err := ValidateToken(r.Context(), h.client, req.Token, audiences)
	if err != nil {
		h.logger.Warn("token validation failed", "err", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	exp := now.Add(h.tokenTTL)
	claims := kidcrypto.Claims{
		Issuer:    h.issuer,
		Subject:   "system:serviceaccount:" + info.Namespace + ":" + info.ServiceAccount,
		Audience:  audiences,
		ClusterID: h.clusterID,
		ExpiresAt: exp,
		IssuedAt:  now,
		NotBefore: now,
	}
	token, err := kidcrypto.SignToken(h.key, h.kid, claims)
	if err != nil {
		h.logger.Error("sign token failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenExchangeResponse{Token: token, ExpiresAt: exp.Unix()})
}

func (h *AgentHandler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (h *AgentHandler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if h.key == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
