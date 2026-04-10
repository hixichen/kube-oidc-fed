package store

import (
	"context"
	"time"
)

type Store interface {
	PutKey(ctx context.Context, kid string, jwk []byte) error
	GetKey(ctx context.Context, kid string) ([]byte, error)
	DeleteKey(ctx context.Context, kid string) error
	ListKeys(ctx context.Context) ([]string, error)
	PutJWKS(ctx context.Context, data []byte) error
	GetJWKS(ctx context.Context) ([]byte, error)
	PutDiscovery(ctx context.Context, data []byte) error
	GetDiscovery(ctx context.Context) ([]byte, error)
	GeneratePresignedPutURL(ctx context.Context, kid string, ttl time.Duration) (string, error)
}
