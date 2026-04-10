package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestPublicKeyToJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := PublicKeyToJWK(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	if jwk.KeyType != "EC" {
		t.Errorf("expected kty=EC, got %s", jwk.KeyType)
	}
	if jwk.Curve != "P-256" {
		t.Errorf("expected crv=P-256, got %s", jwk.Curve)
	}
	if jwk.KeyID != "test-kid" {
		t.Errorf("expected kid=test-kid, got %s", jwk.KeyID)
	}
}

func TestBuildJWKS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := PublicKeyToJWK(&key.PublicKey, "k1")
	jwks := BuildJWKS([]*JWK{jwk})
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
}
