package registry

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

type Handler struct {
	registry  *Registry
	authToken string
	logger    *slog.Logger
}

func NewHandler(reg *Registry, authToken string, logger *slog.Logger) http.Handler {
	h := &Handler{registry: reg, authToken: authToken, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", h.authMiddleware(h.handleRegister))
	mux.HandleFunc("DELETE /keys/{kid}", h.authMiddleware(h.handleDeleteKey))
	mux.HandleFunc("GET /.well-known/openid-configuration", h.handleDiscovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	return mux
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" || token != h.authToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type registerRequest struct {
	KID string          `json:"kid"`
	JWK json.RawMessage `json:"jwk"`
}

type registerResponse struct {
	UploadURL string `json:"upload_url"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.KID == "" {
		http.Error(w, "missing kid", http.StatusBadRequest)
		return
	}
	url, err := h.registry.Register(r.Context(), req.KID, req.JWK)
	if err != nil {
		h.logger.Error("register failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Also store the key immediately (for memory store / testing)
	if len(req.JWK) > 0 {
		if err := h.registry.StoreKey(r.Context(), req.KID, req.JWK); err != nil {
			h.logger.Warn("failed to pre-store key", "err", err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(registerResponse{UploadURL: url})
}

func (h *Handler) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	kid := r.PathValue("kid")
	if kid == "" {
		http.Error(w, "missing kid", http.StatusBadRequest)
		return
	}
	if err := h.registry.DeleteKey(r.Context(), kid); err != nil {
		h.logger.Error("delete key failed", "kid", kid, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	data, err := h.registry.store.GetDiscovery(r.Context())
	if err != nil || len(data) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	data, err := h.registry.store.GetJWKS(r.Context())
	if err != nil || len(data) == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
