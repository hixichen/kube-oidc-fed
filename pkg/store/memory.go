package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type MemoryStore struct {
	mu        sync.RWMutex
	keys      map[string][]byte
	jwks      []byte
	discovery []byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: make(map[string][]byte)}
}

func (m *MemoryStore) PutKey(ctx context.Context, kid string, jwk []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[kid] = jwk
	return nil
}

func (m *MemoryStore) GetKey(ctx context.Context, kid string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %q not found", kid)
	}
	return v, nil
}

func (m *MemoryStore) DeleteKey(ctx context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, kid)
	return nil
}

func (m *MemoryStore) ListKeys(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.keys))
	for k := range m.keys {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *MemoryStore) PutJWKS(ctx context.Context, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jwks = data
	return nil
}

func (m *MemoryStore) GetJWKS(ctx context.Context) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.jwks, nil
}

func (m *MemoryStore) PutDiscovery(ctx context.Context, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.discovery = data
	return nil
}

func (m *MemoryStore) GetDiscovery(ctx context.Context) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.discovery, nil
}

func (m *MemoryStore) GeneratePresignedPutURL(ctx context.Context, kid string, ttl time.Duration) (string, error) {
	return fmt.Sprintf("http://localhost/presigned/%s", kid), nil
}
