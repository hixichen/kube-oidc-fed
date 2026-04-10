package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kidcrypto "github.com/hixichen/kube-kidring/pkg/crypto"
	"github.com/hixichen/kube-kidring/pkg/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"go.uber.org/zap"
)

func TestBrokerInitialize(t *testing.T) {
key, _ := kidcrypto.GenerateKeyPair()
kid, _ := kidcrypto.DeriveKID(&key.PublicKey)
pem, _ := kidcrypto.MarshalPrivateKeyPEM(key)

// Start a mock registry server that handles register and upload
var testSrv *httptest.Server
testSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.Method == "POST" && r.URL.Path == "/register" {
uploadURL := testSrv.URL + "/upload/" + kid
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadURL})
return
}
if r.Method == "PUT" {
w.WriteHeader(http.StatusOK)
return
}
http.NotFound(w, r)
}))
defer testSrv.Close()

client := fake.NewClientset(&corev1.Secret{
ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: "test-ns"},
Data: map[string][]byte{
"private-key.pem": pem,
"kid":             []byte(kid),
},
})

cfg := &config.BrokerConfig{
Namespace:   "test-ns",
SecretName:  "test-secret",
RegistryURL: testSrv.URL,
AuthToken:   "test-token",
}
b := NewBroker(cfg, client, zap.NewNop())
if err := b.Initialize(context.Background()); err != nil {
t.Fatalf("Initialize failed: %v", err)
}
if b.kid == "" {
t.Error("expected non-empty kid after initialize")
}
if b.key == nil {
t.Error("expected non-nil key after initialize")
}
}

func TestBrokerHTTPHandler(t *testing.T) {
key, _ := kidcrypto.GenerateKeyPair()
kid, _ := kidcrypto.DeriveKID(&key.PublicKey)
cfg := &config.BrokerConfig{
TokenTTL:  3600000000000,
AuthToken: "tok",
}
client := fake.NewClientset()
b := &Broker{
cfg:    cfg,
client: client,
key:    key,
kid:    kid,
logger: zap.NewNop(),
}
handler := b.HTTPHandler()
if handler == nil {
t.Fatal("expected non-nil handler")
}
req := httptest.NewRequest("GET", "/healthz", nil)
w := httptest.NewRecorder()
handler.ServeHTTP(w, req)
if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
}

func TestNewBroker(t *testing.T) {
	cfg := &config.BrokerConfig{Namespace: "ns"}
	client := fake.NewClientset()
	b := NewBroker(cfg, client, zap.NewNop())
	if b == nil {
		t.Fatal("expected non-nil broker")
	}
	if b.cfg != cfg {
		t.Error("cfg mismatch")
	}
}

func TestBrokerInitializeRegistryFails(t *testing.T) {
	// Registry returns error on /register
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := fake.NewClientset()
	cfg := &config.BrokerConfig{
		Namespace:   "ns",
		SecretName:  "sec",
		RegistryURL: srv.URL,
		AuthToken:   "tok",
	}
	b := NewBroker(cfg, client, zap.NewNop())
	// Use short timeout to avoid long retry waits
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := b.Initialize(ctx)
	if err == nil {
		t.Fatal("expected error when registry fails")
	}
}

func TestBrokerInitializeWithNewKey(t *testing.T) {
	// No pre-existing secret → generates new key
	var uploadSrv *httptest.Server
	uploadSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer uploadSrv.Close()

	var regSrv *httptest.Server
	regSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client := fake.NewClientset() // no secret
	cfg := &config.BrokerConfig{
		Namespace:   "ns",
		SecretName:  "new-secret",
		RegistryURL: regSrv.URL,
		AuthToken:   "tok",
	}
	b := NewBroker(cfg, client, zap.NewNop())
	if err := b.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if b.kid == "" {
		t.Error("expected non-empty kid")
	}
}
