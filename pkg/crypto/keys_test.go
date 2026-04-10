package crypto

import (
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestDeriveKID(t *testing.T) {
	key, _ := GenerateKeyPair()
	kid, err := DeriveKID(&key.PublicKey)
	if err != nil {
		t.Fatalf("DeriveKID: %v", err)
	}
	if len(kid) != 16 {
		t.Fatalf("expected 16 chars, got %d", len(kid))
	}
	// deterministic
	kid2, _ := DeriveKID(&key.PublicKey)
	if kid != kid2 {
		t.Fatal("KID not deterministic")
	}
}

func TestMarshalUnmarshalPrivateKey(t *testing.T) {
	key, _ := GenerateKeyPair()
	pem, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	key2, err := UnmarshalPrivateKeyPEM(pem)
	if err != nil {
		t.Fatalf("UnmarshalPrivateKeyPEM: %v", err)
	}
	if key.D.Cmp(key2.D) != 0 {
		t.Fatal("keys differ")
	}
}

func TestUnmarshalPrivateKeyPEM_Invalid(t *testing.T) {
_, err := UnmarshalPrivateKeyPEM([]byte("not-pem"))
if err == nil {
t.Fatal("expected error for invalid PEM")
}
}

func TestUnmarshalPrivateKeyPEM_BadKey(t *testing.T) {
_, err := UnmarshalPrivateKeyPEM([]byte("-----BEGIN EC PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----\n"))
if err == nil {
t.Fatal("expected error for bad key data")
}
}

func TestMarshalUnmarshalRoundtrip(t *testing.T) {
key, err := GenerateKeyPair()
if err != nil {
t.Fatalf("generate: %v", err)
}
pem, err := MarshalPrivateKeyPEM(key)
if err != nil {
t.Fatalf("marshal: %v", err)
}
loaded, err := UnmarshalPrivateKeyPEM(pem)
if err != nil {
t.Fatalf("unmarshal: %v", err)
}
if loaded.D.Cmp(key.D) != 0 {
t.Error("key mismatch after roundtrip")
}
}

func TestSignTokenWithExtra(t *testing.T) {
key, _ := GenerateKeyPair()
kid, _ := DeriveKID(&key.PublicKey)
claims := Claims{
Issuer:    "test",
Subject:   "sub",
Audience:  []string{"aud"},
ClusterID: "c1",
ExpiresAt: time.Now().Add(time.Hour),
IssuedAt:  time.Now(),
NotBefore: time.Now(),
Extra:     map[string]interface{}{"custom": "value"},
}
token, err := SignToken(key, kid, claims)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if token == "" {
t.Error("expected non-empty token")
}
}
