package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRegisterKey_Success(t *testing.T) {
var uploadSrv *httptest.Server
uploadSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
}))
defer uploadSrv.Close()

var registrySrv *httptest.Server
registrySrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.Method == "POST" && r.URL.Path == "/register" {
json.NewEncoder(w).Encode(map[string]string{"upload_url": uploadSrv.URL + "/upload"})
return
}
http.NotFound(w, r)
}))
defer registrySrv.Close()

jwk := []byte(`{"kty":"EC","kid":"test"}`)
url, err := RegisterKey(context.Background(), registrySrv.URL, "token", "test-kid", jwk, zap.NewNop())
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if url == "" {
t.Error("expected non-empty URL")
}
}

func TestRegisterKey_RegistryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Use short timeout context to avoid long retry waits
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := RegisterKey(ctx, srv.URL, "token", "kid", []byte(`{}`), zap.NewNop())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRegisterKey_ContextCancelled(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
http.Error(w, "server error", http.StatusInternalServerError)
}))
defer srv.Close()

ctx, cancel := context.WithCancel(context.Background())
cancel() // cancel immediately
_, err := RegisterKey(ctx, srv.URL, "token", "kid", []byte(`{}`), zap.NewNop())
if err == nil {
t.Fatal("expected error for cancelled context")
}
}

func TestReissuePresignedURL_Success(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.Method == "POST" {
json.NewEncoder(w).Encode(map[string]string{"upload_url": "http://example.com/upload"})
return
}
http.NotFound(w, r)
}))
defer srv.Close()

url, err := ReissuePresignedURL(context.Background(), srv.URL, "token", "test-kid", zap.NewNop())
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if url == "" {
t.Error("expected non-empty URL")
}
}

func TestReissuePresignedURL_Error(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
http.Error(w, "not found", http.StatusNotFound)
}))
defer srv.Close()

_, err := ReissuePresignedURL(context.Background(), srv.URL, "token", "bad-kid", zap.NewNop())
if err == nil {
t.Fatal("expected error")
}
}

func TestUploadToURL_Success(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.WriteHeader(http.StatusOK)
}))
defer srv.Close()

if err := uploadToURL(context.Background(), srv.URL, []byte(`{"test":true}`)); err != nil {
t.Fatalf("unexpected error: %v", err)
}
}

func TestUploadToURL_Error(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
http.Error(w, "forbidden", http.StatusForbidden)
}))
defer srv.Close()

if err := uploadToURL(context.Background(), srv.URL, []byte(`{}`)); err == nil {
t.Fatal("expected error for non-2xx status")
}
}

func TestRegisterKey_BadDecodeResponse(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
if r.URL.Path == "/register" {
w.Write([]byte("not-json"))
return
}
}))
defer srv.Close()

_, err := RegisterKey(context.Background(), srv.URL, "token", "kid", []byte(`{}`), zap.NewNop())
if err == nil {
t.Fatal("expected error for bad JSON response")
}
}

func TestReissuePresignedURL_BadJSON(t *testing.T) {
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Write([]byte("not-json"))
}))
defer srv.Close()

_, err := ReissuePresignedURL(context.Background(), srv.URL, "token", "kid", zap.NewNop())
if err == nil {
t.Fatal("expected error for bad JSON response")
}
}

func TestUploadToURL_InvalidURL(t *testing.T) {
err := uploadToURL(context.Background(), "://invalid", []byte(`{}`))
if err == nil {
t.Fatal("expected error for invalid URL")
}
}
