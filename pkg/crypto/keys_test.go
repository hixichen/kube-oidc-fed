package crypto

import (
	"testing"
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
