package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/hixichen/kube-oidc-fed/pkg/config"
	kidcrypto "github.com/hixichen/kube-oidc-fed/pkg/crypto"
	"go.uber.org/zap"
)

func makeAuthTokenReview(authenticated bool, username string) *authv1.TokenReview {
return &authv1.TokenReview{
TypeMeta: metav1.TypeMeta{
Kind:       "TokenReview",
APIVersion: "authentication.k8s.io/v1",
},
Status: authv1.TokenReviewStatus{
Authenticated: authenticated,
User: authv1.UserInfo{
Username: username,
UID:      "uid-1",
},
},
}
}

func newTestBrokerHandler(t *testing.T, authToken string) (*BrokerHandler, *fake.Clientset) {
t.Helper()
key, err := kidcrypto.GenerateKeyPair()
if err != nil {
t.Fatalf("generate key: %v", err)
}
kid, err := kidcrypto.DeriveKID(&key.PublicKey)
if err != nil {
t.Fatalf("derive kid: %v", err)
}
cfg := &config.BrokerConfig{
Issuer:    "https://issuer.example.com",
Audience:  []string{"test-audience"},
ClusterID: "test-cluster",
TokenTTL:  time.Hour,
AuthToken: authToken,
}
client := fake.NewClientset()
h := &BrokerHandler{
client: client,
key:    key,
kid:    kid,
cfg:    cfg,
logger: zap.NewNop(),
}
return h, client
}

func TestBrokerHandlerHealthz(t *testing.T) {
h, _ := newTestBrokerHandler(t, "tok")
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
req := httptest.NewRequest("GET", "/healthz", nil)
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
if w.Body.String() != "ok" {
t.Errorf("expected 'ok', got %q", w.Body.String())
}
}

func TestBrokerHandlerReadyz(t *testing.T) {
h, _ := newTestBrokerHandler(t, "tok")
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
req := httptest.NewRequest("GET", "/readyz", nil)
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestBrokerHandlerReadyzNotReady(t *testing.T) {
cfg := &config.BrokerConfig{AuthToken: "tok"}
client := fake.NewClientset()
mux := NewBrokerHandler(client, nil, "", cfg, zap.NewNop())
req := httptest.NewRequest("GET", "/readyz", nil)
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusServiceUnavailable {
t.Fatalf("expected 503, got %d", w.Code)
}
}

func TestBrokerHandlerTokenExchangeUnauthorized(t *testing.T) {
h, client := newTestBrokerHandler(t, "tok")
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, &authv1.TokenReview{
TypeMeta: metav1.TypeMeta{Kind: "TokenReview", APIVersion: "authentication.k8s.io/v1"},
Status:   authv1.TokenReviewStatus{Authenticated: false, Error: "invalid"},
}, nil
})
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
body, _ := json.Marshal(tokenExchangeRequest{Token: "bad-token"})
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader(body))
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusUnauthorized {
t.Fatalf("expected 401, got %d", w.Code)
}
}

func TestBrokerHandlerTokenExchangeMissingToken(t *testing.T) {
h, _ := newTestBrokerHandler(t, "tok")
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
body, _ := json.Marshal(tokenExchangeRequest{Token: ""})
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader(body))
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("expected 400, got %d", w.Code)
}
}

func TestBrokerHandlerTokenExchangeBadJSON(t *testing.T) {
h, _ := newTestBrokerHandler(t, "tok")
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader([]byte("not-json")))
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("expected 400, got %d", w.Code)
}
}

func TestBrokerHandlerTokenExchangeSuccess(t *testing.T) {
h, client := newTestBrokerHandler(t, "tok")
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeAuthTokenReview(true, "system:serviceaccount:default:my-sa"), nil
})
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
body, _ := json.Marshal(tokenExchangeRequest{Token: "valid-token"})
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader(body))
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
}
var resp tokenExchangeResponse
if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
t.Fatalf("decode response: %v", err)
}
if resp.Token == "" {
t.Error("expected non-empty token")
}
if resp.ExpiresAt == 0 {
t.Error("expected non-zero expires_at")
}
}

func TestBrokerHandlerTokenExchangeExtraClaims(t *testing.T) {
h, client := newTestBrokerHandler(t, "tok")
h.cfg.JWTExtraClaims = map[string]string{"env": "prod"}
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeAuthTokenReview(true, "system:serviceaccount:default:my-sa"), nil
})
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
body, _ := json.Marshal(tokenExchangeRequest{Token: "valid-token"})
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader(body))
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestBrokerHandlerRotateUnauthorized(t *testing.T) {
h, _ := newTestBrokerHandler(t, "tok")
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
req := httptest.NewRequest("POST", "/admin/rotate", nil)
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusUnauthorized {
t.Fatalf("expected 401, got %d", w.Code)
}
}

func TestBuildSubjectDefaultTemplate(t *testing.T) {
h := &BrokerHandler{
cfg:    &config.BrokerConfig{},
logger: zap.NewNop(),
}
info := &TokenInfo{Namespace: "mynamespace", ServiceAccount: "mysa"}
subject := h.buildSubject(info)
expected := "system:serviceaccount:mynamespace:mysa"
if subject != expected {
t.Errorf("expected %q, got %q", expected, subject)
}
}

func TestBuildSubjectCustomTemplate(t *testing.T) {
h := &BrokerHandler{
cfg:    &config.BrokerConfig{JWTSubjectTemplate: "{{.ServiceAccount}}@{{.Namespace}}"},
logger: zap.NewNop(),
}
info := &TokenInfo{Namespace: "ns", ServiceAccount: "sa"}
subject := h.buildSubject(info)
expected := "sa@ns"
if subject != expected {
t.Errorf("expected %q, got %q", expected, subject)
}
}

func TestBuildSubjectInvalidTemplate(t *testing.T) {
h := &BrokerHandler{
cfg:    &config.BrokerConfig{JWTSubjectTemplate: "{{.Invalid"},
logger: zap.NewNop(),
}
info := &TokenInfo{Namespace: "ns", ServiceAccount: "sa"}
subject := h.buildSubject(info)
if subject == "" {
t.Error("expected non-empty fallback subject")
}
}

func TestBrokerHandlerTokenExchangeCustomAudience(t *testing.T) {
h, client := newTestBrokerHandler(t, "tok")
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeAuthTokenReview(true, "system:serviceaccount:default:my-sa"), nil
})
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)
body, _ := json.Marshal(tokenExchangeRequest{Token: "valid-token", Audiences: []string{"custom-aud"}})
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader(body))
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
}
}

func TestTokenExchangeWithContext(t *testing.T) {
h, client := newTestBrokerHandler(t, "tok")
client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, makeAuthTokenReview(true, "system:serviceaccount:kube-system:default"), nil
})
mux := NewBrokerHandler(h.client, h.key, h.kid, h.cfg, h.logger)

body, _ := json.Marshal(tokenExchangeRequest{Token: "valid-token"})
req := httptest.NewRequest("POST", "/token/exchange", bytes.NewReader(body))
req = req.WithContext(context.Background())
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestBrokerHandlerRotateSuccess(t *testing.T) {
key, _ := kidcrypto.GenerateKeyPair()
kid, _ := kidcrypto.DeriveKID(&key.PublicKey)

var uploadSrv *httptest.Server
uploadSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
}))
defer uploadSrv.Close()

var regSrv *httptest.Server
regSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.Method == "POST" && r.URL.Path == "/reissue/"+kid {
json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadSrv.URL + "/upload"})
return
}
if r.Method == "POST" && r.URL.Path == "/register" {
json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadSrv.URL + "/upload"})
return
}
if r.Method == "PUT" {
w.WriteHeader(http.StatusOK)
return
}
http.NotFound(w, r)
}))
defer regSrv.Close()

cfg := &config.BrokerConfig{
Namespace:   "test-ns",
SecretName:  "test-secret",
RegistryURL: regSrv.URL,
AuthToken:   "tok",
TokenTTL:    time.Hour,
}
client := fake.NewClientset()
// Pre-create a secret
pem, _ := kidcrypto.MarshalPrivateKeyPEM(key)
secret := &corev1.Secret{
ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "test-ns"},
Data: map[string][]byte{
"private-key.pem": pem,
"kid":             []byte(kid),
},
}
client.CoreV1().Secrets("test-ns").Create(context.Background(), secret, metav1.CreateOptions{})

mux := NewBrokerHandler(client, key, kid, cfg, zap.NewNop())
req := httptest.NewRequest("POST", "/admin/rotate", nil)
req.Header.Set("Authorization", "Bearer tok")
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
}
var resp rotateResponse
if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
t.Fatalf("decode: %v", err)
}
if resp.KID == "" {
t.Error("expected non-empty KID")
}
}

func TestBrokerHandlerRotateReissueError(t *testing.T) {
key, _ := kidcrypto.GenerateKeyPair()
kid, _ := kidcrypto.DeriveKID(&key.PublicKey)

// Registry returns error for reissue
regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
http.Error(w, "not found", http.StatusNotFound)
}))
defer regSrv.Close()

cfg := &config.BrokerConfig{
RegistryURL: regSrv.URL,
AuthToken:   "tok",
Namespace:   "ns",
SecretName:  "sec",
}
client := fake.NewClientset()
mux := NewBrokerHandler(client, key, kid, cfg, zap.NewNop())
req := httptest.NewRequest("POST", "/admin/rotate", nil)
req.Header.Set("Authorization", "Bearer tok")
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusInternalServerError {
t.Fatalf("expected 500, got %d", w.Code)
}
}

func TestBrokerHandlerRotateRegisterNewKeyError(t *testing.T) {
	key, _ := kidcrypto.GenerateKeyPair()
	kid, _ := kidcrypto.DeriveKID(&key.PublicKey)

	var uploadSrv *httptest.Server
	uploadSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer uploadSrv.Close()

	callCount := 0
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/reissue/"+kid {
			json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadSrv.URL + "/up"})
			return
		}
		// Fail /register for the new key
		if r.Method == "POST" && r.URL.Path == "/register" {
			callCount++
			http.Error(w, "fail", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer regSrv.Close()

	cfg := &config.BrokerConfig{
		RegistryURL: regSrv.URL,
		AuthToken:   "tok",
		Namespace:   "ns",
		SecretName:  "sec",
	}
	client := fake.NewClientset()
	mux := NewBrokerHandler(client, key, kid, cfg, zap.NewNop())
	// Use short timeout context to avoid long retry waits
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, "POST", "/admin/rotate", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	// Should fail since register returns error
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestBrokerHandlerRotateStoreKeyError(t *testing.T) {
key, _ := kidcrypto.GenerateKeyPair()
kid, _ := kidcrypto.DeriveKID(&key.PublicKey)

var uploadSrv *httptest.Server
uploadSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
}))
defer uploadSrv.Close()

regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.Method == "POST" && r.URL.Path == "/reissue/"+kid {
json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadSrv.URL + "/up"})
return
}
if r.Method == "POST" && r.URL.Path == "/register" {
json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadSrv.URL + "/up"})
return
}
if r.Method == "PUT" {
w.WriteHeader(http.StatusOK)
return
}
http.NotFound(w, r)
}))
defer regSrv.Close()

cfg := &config.BrokerConfig{
RegistryURL: regSrv.URL,
AuthToken:   "tok",
Namespace:   "test-ns",
SecretName:  "test-secret",
}
client := fake.NewClientset()
// Make ALL secrets operations (create/update) fail
client.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, nil, fmt.Errorf("permission denied")
})
client.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
return true, nil, fmt.Errorf("permission denied")
})

mux := NewBrokerHandler(client, key, kid, cfg, zap.NewNop())
req := httptest.NewRequest("POST", "/admin/rotate", nil)
req.Header.Set("Authorization", "Bearer tok")
w := httptest.NewRecorder()
mux.ServeHTTP(w, req)
if w.Code != http.StatusInternalServerError {
t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
}
}
