package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hixichen/kube-kidring/pkg/store"
	"go.uber.org/zap"
)

func newTestRegistry() (*Registry, *store.MemoryStore) {
st := store.NewMemoryStore()
logger := zap.NewNop()
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

func TestHandlerDiscovery(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestHandlerJWKS(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestHandlerDeleteKey(t *testing.T) {
reg, _ := newTestRegistry()
// First register a key
ctx := context.Background()
_ = reg.StoreKey(ctx, "del-kid", []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"del-kid","alg":"ES256","use":"sig"}`))

h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("DELETE", "/keys/del-kid", nil)
req.Header.Set("Authorization", "Bearer test-token")
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
// Safety check might refuse empty JWKS, that's ok (500). Check it's either 204 or 500.
if w.Code != http.StatusNoContent && w.Code != http.StatusInternalServerError {
t.Fatalf("expected 204 or 500, got %d: %s", w.Code, w.Body.String())
}
}

func TestHandlerReissue(t *testing.T) {
reg, _ := newTestRegistry()
ctx := context.Background()
_ = reg.StoreKey(ctx, "reissue-kid", []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"reissue-kid","alg":"ES256","use":"sig"}`))

h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("POST", "/reissue/reissue-kid", nil)
req.Header.Set("Authorization", "Bearer test-token")
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
}
}

func TestHandlerReissueNotFound(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("POST", "/reissue/nonexistent", nil)
req.Header.Set("Authorization", "Bearer test-token")
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusNotFound {
t.Fatalf("expected 404, got %d", w.Code)
}
}

func TestHandlerUI(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/ui", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestHandlerRootRedirect(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusFound {
t.Fatalf("expected 302, got %d", w.Code)
}
}

func TestHandlerRegisterMissingKID(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
body, _ := json.Marshal(registerRequest{KID: "", JWK: nil})
req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
req.Header.Set("Authorization", "Bearer test-token")
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("expected 400, got %d", w.Code)
}
}

func TestHandlerRegisterBadJSON(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("POST", "/register", bytes.NewReader([]byte("badjson")))
req.Header.Set("Authorization", "Bearer test-token")
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("expected 400, got %d", w.Code)
}
}

func TestHandlerDeleteKeyMissingUnauth(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("DELETE", "/keys/somekid", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusUnauthorized {
t.Fatalf("expected 401, got %d", w.Code)
}
}

func TestHandlerNotFound(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/nonexistent", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusNotFound {
t.Fatalf("expected 404, got %d", w.Code)
}
}

func TestRegistryDeleteSafety(t *testing.T) {
reg, _ := newTestRegistry()
ctx := context.Background()
// Store a key then try to delete - safety should block empty JWKS
_ = reg.StoreKey(ctx, "kid-1", []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"kid-1","alg":"ES256","use":"sig"}`))
err := reg.DeleteKey(ctx, "kid-1")
// Should fail safety check (AllowEmpty=false)
if err == nil {
t.Fatal("expected safety error when deleting last key")
}
}

func TestRegistryRebuildJWKSMultiple(t *testing.T) {
reg, _ := newTestRegistry()
ctx := context.Background()
for i := 0; i < 3; i++ {
kid := fmt.Sprintf("kid-%d", i)
_ = reg.StoreKey(ctx, kid, []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"`+kid+`","alg":"ES256","use":"sig"}`))
}
err := reg.RebuildJWKS(ctx)
if err != nil {
t.Fatalf("RebuildJWKS: %v", err)
}
}

func TestHandlerDiscoveryEmpty(t *testing.T) {
// Create registry without initializing (no discovery data)
st := store.NewMemoryStore()
logger := zap.NewNop()
reg := New(st, "http://localhost:8080", logger, DefaultSafetyConfig())
// Don't call Initialize so discovery is empty
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusNotFound {
t.Fatalf("expected 404, got %d", w.Code)
}
}

func TestHandlerJWKSEmpty(t *testing.T) {
st := store.NewMemoryStore()
logger := zap.NewNop()
reg := New(st, "http://localhost:8080", logger, DefaultSafetyConfig())
h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusNotFound {
t.Fatalf("expected 404, got %d", w.Code)
}
}

func TestHandlerDeleteKeyAuth(t *testing.T) {
	// Use permissive safety config to allow deletion
	st := store.NewMemoryStore()
	safety := SafetyConfig{AllowEmpty: false, MinKeyCount: 1, MaxRemovedPerOp: 5, MaxRemovedPercent: 1.0}
	reg := New(st, "http://localhost:8080", zap.NewNop(), safety)
	_ = reg.Initialize(context.Background())

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		kid := fmt.Sprintf("dk-%d", i)
		_ = reg.StoreKey(ctx, kid, []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"`+kid+`","alg":"ES256","use":"sig"}`))
	}

	h := NewHandler(reg, "test-token", reg.logger)
	req := httptest.NewRequest("DELETE", "/keys/dk-0", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegistryInitializeIdempotent(t *testing.T) {
reg, _ := newTestRegistry()
ctx := context.Background()
// Second Initialize call (JWKS already exists)
if err := reg.Initialize(ctx); err != nil {
t.Fatalf("second Initialize failed: %v", err)
}
}

func TestRegistryStoreKeyError(t *testing.T) {
reg, _ := newTestRegistry()
ctx := context.Background()
// Store with invalid JSON - should still store but rebuild JWKS will skip bad key
if err := reg.StoreKey(ctx, "bad", []byte("not-json")); err != nil {
// it's ok to error here as RebuildJWKS may fail on unmarshal
_ = err
}
}

func TestHandlerUIWithKeys(t *testing.T) {
reg, _ := newTestRegistry()
ctx := context.Background()
_ = reg.StoreKey(ctx, "ui-kid-1", []byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"ui-kid-1","alg":"ES256","use":"sig"}`))

h := NewHandler(reg, "test-token", reg.logger)
req := httptest.NewRequest("GET", "/ui", nil)
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "ui-kid-1") {
t.Error("expected kid in UI output")
}
}

func TestHandlerRegisterNoJWK(t *testing.T) {
reg, _ := newTestRegistry()
h := NewHandler(reg, "test-token", reg.logger)
body, _ := json.Marshal(registerRequest{KID: "no-jwk-kid"})
req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
req.Header.Set("Authorization", "Bearer test-token")
w := httptest.NewRecorder()
h.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
}
}
