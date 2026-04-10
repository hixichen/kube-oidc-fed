package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// mockS3Client implements s3API for testing.
type mockS3Client struct {
	objects map[string][]byte
	errOn   string // key prefix to trigger errors on
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{objects: make(map[string][]byte)}
}

func (m *mockS3Client) PutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	key := aws.ToString(params.Key)
	if m.errOn != "" && strings.HasPrefix(key, m.errOn) {
		return nil, fmt.Errorf("mock put error")
	}
	data, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	m.objects[key] = data
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) GetObject(_ context.Context, params *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(params.Key)
	if m.errOn != "" && strings.HasPrefix(key, m.errOn) {
		return nil, fmt.Errorf("mock get error")
	}
	data, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(data))}, nil
}

func (m *mockS3Client) DeleteObject(_ context.Context, params *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	key := aws.ToString(params.Key)
	if m.errOn != "" && strings.HasPrefix(key, m.errOn) {
		return nil, fmt.Errorf("mock delete error")
	}
	delete(m.objects, key)
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockS3Client) ListObjectsV2(_ context.Context, params *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.errOn == "list" {
		return nil, fmt.Errorf("mock list error")
	}
	prefix := aws.ToString(params.Prefix)
	var contents []types.Object
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			k := k // capture
			contents = append(contents, types.Object{Key: aws.String(k)})
		}
	}
	return &s3.ListObjectsV2Output{Contents: contents}, nil
}

// mockPresigner implements s3PresignAPI for testing.
type mockPresigner struct {
	err bool
}

func (m *mockPresigner) PresignPutObject(_ context.Context, params *s3.PutObjectInput, _ ...func(*s3.PresignOptions)) (*s3PresignedRequest, error) {
	if m.err {
		return nil, fmt.Errorf("mock presign error")
	}
	return &s3PresignedRequest{URL: "https://mock-presigned/" + aws.ToString(params.Key)}, nil
}

func newTestS3Store() (*S3Store, *mockS3Client) {
	mock := newMockS3Client()
	presigner := &mockPresigner{}
	st := newS3StoreWithAPIs(mock, presigner, "test-bucket")
	return st, mock
}

func TestS3StorePutGetKey(t *testing.T) {
	st, _ := newTestS3Store()
	ctx := context.Background()

	data := []byte(`{"kty":"EC","kid":"kid1"}`)
	if err := st.PutKey(ctx, "kid1", data); err != nil {
		t.Fatalf("PutKey: %v", err)
	}
	got, err := st.GetKey(ctx, "kid1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("expected %q, got %q", data, got)
	}
}

func TestS3StoreGetKeyNotFound(t *testing.T) {
	st, _ := newTestS3Store()
	_, err := st.GetKey(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestS3StorePutKeyError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = "keys/"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	err := st.PutKey(context.Background(), "kid1", []byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StoreGetKeyError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = "keys/"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	_, err := st.GetKey(context.Background(), "kid1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StoreDeleteKey(t *testing.T) {
	st, mock := newTestS3Store()
	ctx := context.Background()
	mock.objects["keys/kid1.json"] = []byte(`{"kid":"kid1"}`)

	if err := st.DeleteKey(ctx, "kid1"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, ok := mock.objects["keys/kid1.json"]; ok {
		t.Error("expected key to be deleted")
	}
}

func TestS3StoreDeleteKeyError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = "keys/"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	err := st.DeleteKey(context.Background(), "kid1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StoreListKeys(t *testing.T) {
	st, mock := newTestS3Store()
	ctx := context.Background()
	mock.objects["keys/kid1.json"] = []byte("d1")
	mock.objects["keys/kid2.json"] = []byte("d2")
	mock.objects[".well-known/jwks.json"] = []byte("jwks") // should not be listed

	kids, err := st.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(kids) != 2 {
		t.Errorf("expected 2 kids, got %d: %v", len(kids), kids)
	}
	for _, k := range kids {
		if k != "kid1" && k != "kid2" {
			t.Errorf("unexpected kid: %q", k)
		}
	}
}

func TestS3StoreListKeysError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = "list"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	_, err := st.ListKeys(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StorePutGetJWKS(t *testing.T) {
	st, _ := newTestS3Store()
	ctx := context.Background()
	data := []byte(`{"keys":[]}`)

	if err := st.PutJWKS(ctx, data); err != nil {
		t.Fatalf("PutJWKS: %v", err)
	}
	got, err := st.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("expected %q, got %q", data, got)
	}
}

func TestS3StorePutJWKSError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = ".well-known"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	err := st.PutJWKS(context.Background(), []byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StoreGetJWKSError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = ".well-known"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	_, err := st.GetJWKS(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StorePutGetDiscovery(t *testing.T) {
	st, _ := newTestS3Store()
	ctx := context.Background()
	data := []byte(`{"issuer":"https://example.com"}`)

	if err := st.PutDiscovery(ctx, data); err != nil {
		t.Fatalf("PutDiscovery: %v", err)
	}
	got, err := st.GetDiscovery(ctx)
	if err != nil {
		t.Fatalf("GetDiscovery: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("expected %q, got %q", data, got)
	}
}

func TestS3StorePutDiscoveryError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = ".well-known"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	err := st.PutDiscovery(context.Background(), []byte("data"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StoreGetDiscoveryError(t *testing.T) {
	mock := newMockS3Client()
	mock.errOn = ".well-known"
	st := newS3StoreWithAPIs(mock, &mockPresigner{}, "bucket")
	_, err := st.GetDiscovery(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestS3StoreGeneratePresignedPutURL(t *testing.T) {
	st, _ := newTestS3Store()
	url, err := st.GeneratePresignedPutURL(context.Background(), "kid1", time.Minute)
	if err != nil {
		t.Fatalf("GeneratePresignedPutURL: %v", err)
	}
	if url == "" {
		t.Error("expected non-empty URL")
	}
	if !strings.Contains(url, "kid1") {
		t.Errorf("expected URL to contain kid, got %q", url)
	}
}

func TestS3StoreGeneratePresignedPutURLError(t *testing.T) {
	st := newS3StoreWithAPIs(newMockS3Client(), &mockPresigner{err: true}, "bucket")
	_, err := st.GeneratePresignedPutURL(context.Background(), "kid1", time.Minute)
	if err == nil {
		t.Fatal("expected error")
	}
}
