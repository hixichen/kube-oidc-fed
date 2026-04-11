package store

import (
	"context"
	"fmt"
	"strings"
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

func TestMemoryStoreDiscovery(t *testing.T) {
s := NewMemoryStore()
ctx := context.Background()

// GetDiscovery on empty store
data, err := s.GetDiscovery(ctx)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if len(data) != 0 {
t.Errorf("expected empty, got %q", data)
}

// PutDiscovery
doc := []byte(`{"issuer":"https://example.com"}`)
if err := s.PutDiscovery(ctx, doc); err != nil {
t.Fatalf("PutDiscovery: %v", err)
}

// GetDiscovery after put
got, err := s.GetDiscovery(ctx)
if err != nil {
t.Fatalf("GetDiscovery: %v", err)
}
if string(got) != string(doc) {
t.Errorf("expected %q, got %q", doc, got)
}
}

func TestMemoryStoreJWKS(t *testing.T) {
s := NewMemoryStore()
ctx := context.Background()

// GetJWKS on empty store
data, err := s.GetJWKS(ctx)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if len(data) != 0 {
t.Errorf("expected empty, got %q", data)
}

// PutJWKS
jwks := []byte(`{"keys":[]}`)
if err := s.PutJWKS(ctx, jwks); err != nil {
t.Fatalf("PutJWKS: %v", err)
}

got, err := s.GetJWKS(ctx)
if err != nil {
t.Fatalf("GetJWKS: %v", err)
}
if string(got) != string(jwks) {
t.Errorf("expected %q, got %q", jwks, got)
}
}

func TestMemoryStoreKeyNotFound(t *testing.T) {
s := NewMemoryStore()
ctx := context.Background()
_, err := s.GetKey(ctx, "nonexistent")
if err == nil {
t.Fatal("expected error for missing key")
}
}

func TestMemoryStoreDeleteNonExistent(t *testing.T) {
s := NewMemoryStore()
ctx := context.Background()
// Should not error
if err := s.DeleteKey(ctx, "nonexistent"); err != nil {
t.Fatalf("unexpected error: %v", err)
}
}

func TestMemoryStorePresignedURL(t *testing.T) {
s := NewMemoryStore()
ctx := context.Background()
url, err := s.GeneratePresignedPutURL(ctx, "test-kid", time.Minute)
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if url == "" {
t.Error("expected non-empty URL")
}
if !strings.Contains(url, "test-kid") {
t.Errorf("expected URL to contain kid, got %q", url)
}
}

func TestMemoryStoreMultipleKeys(t *testing.T) {
s := NewMemoryStore()
ctx := context.Background()
for i := 0; i < 5; i++ {
kid := fmt.Sprintf("kid-%d", i)
if err := s.PutKey(ctx, kid, []byte("data-"+kid)); err != nil {
t.Fatalf("PutKey: %v", err)
}
}
keys, err := s.ListKeys(ctx)
if err != nil {
t.Fatalf("ListKeys: %v", err)
}
if len(keys) != 5 {
t.Errorf("expected 5 keys, got %d", len(keys))
}
}
