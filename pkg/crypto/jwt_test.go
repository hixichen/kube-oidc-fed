package crypto

import (
	"testing"
	"time"
)

func TestSignToken(t *testing.T) {
	key, _ := GenerateKeyPair()
	kid, _ := DeriveKID(&key.PublicKey)
	now := time.Now()
	claims := Claims{
		Issuer:    "https://test.example.com",
		Subject:   "system:serviceaccount:default:test",
		Audience:  []string{"sts.amazonaws.com"},
		ClusterID: "cluster-1",
		ExpiresAt: now.Add(time.Hour),
		IssuedAt:  now,
		NotBefore: now,
	}
	token, err := SignToken(key, kid, claims)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
}
