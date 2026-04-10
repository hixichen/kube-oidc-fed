package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hixichen/kube-kidring/pkg/store"
)

func newTestRegistry() (*Registry, *store.MemoryStore) {
	st := store.NewMemoryStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	reg := New(st, "http://localhost:8080", logger, DefaultSafetyConfig())
	_ = reg.Initialize(context.Background())
	return reg, st
}

func TestHandlerHealthz(t *testing.T) {
	reg, _ := newTestRegistry()
	h := NewHandler(reg, "test-token", reg.logger)
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandlerRegister(t *testing.T) {
	reg, _ := newTestRegistry()
	h := NewHandler(reg, "test-token", reg.logger)

	body := registerRequest{
		KID: "test-kid",
		JWK: json.RawMessage(`{"kty":"EC","crv":"P-256","x":"test","y":"test","kid":"test-kid","alg":"ES256","use":"sig"}`),
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/register", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlerRegisterUnauth(t *testing.T) {
	reg, _ := newTestRegistry()
	h := NewHandler(reg, "test-token", reg.logger)
	req := httptest.NewRequest("POST", "/register", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
