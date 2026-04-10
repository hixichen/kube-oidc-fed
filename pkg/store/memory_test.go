package store

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	// PutKey / GetKey
	if err := s.PutKey(ctx, "kid1", []byte(`{"kid":"kid1"}`)); err != nil {
		t.Fatal(err)
	}
	val, err := s.GetKey(ctx, "kid1")
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != `{"kid":"kid1"}` {
		t.Fatalf("unexpected value: %s", val)
	}

	// ListKeys
	keys, err := s.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// DeleteKey
	if err := s.DeleteKey(ctx, "kid1"); err != nil {
		t.Fatal(err)
	}
	keys, _ = s.ListKeys(ctx)
	if len(keys) != 0 {
		t.Fatal("expected 0 keys after delete")
	}

	// JWKS
	if err := s.PutJWKS(ctx, []byte(`{"keys":[]}`)); err != nil {
		t.Fatal(err)
	}
	jwks, err := s.GetJWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(jwks) != `{"keys":[]}` {
		t.Fatalf("unexpected jwks: %s", jwks)
	}

	// Presigned
	url, err := s.GeneratePresignedPutURL(ctx, "kid1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if url == "" {
		t.Fatal("empty presigned URL")
	}
}
