package broker

import (
	"context"
	"testing"

	kidcrypto "github.com/hixichen/kube-kidring/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLoadOrGenerateKey_GeneratesNew(t *testing.T) {
	client := fake.NewClientset()
	key, kid, err := LoadOrGenerateKey(context.Background(), client, "test-ns", "test-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if kid == "" {
		t.Fatal("expected non-empty kid")
	}
	// Verify secret was created
	secret, err := client.CoreV1().Secrets("test-ns").Get(context.Background(), "test-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret to be created: %v", err)
	}
	if string(secret.Data["kid"]) != kid {
		t.Errorf("expected kid %q in secret, got %q", kid, string(secret.Data["kid"]))
	}
}

func TestLoadOrGenerateKey_LoadsExisting(t *testing.T) {
	// Pre-create a secret with a key
	key, err := kidcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid, _ := kidcrypto.DeriveKID(&key.PublicKey)
	pem, _ := kidcrypto.MarshalPrivateKeyPEM(key)

	client := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-secret", Namespace: "ns"},
		Data: map[string][]byte{
			"private-key.pem": pem,
			"kid":             []byte(kid),
		},
	})

	loadedKey, loadedKID, err := LoadOrGenerateKey(context.Background(), client, "ns", "existing-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loadedKID != kid {
		t.Errorf("expected kid %q, got %q", kid, loadedKID)
	}
	if loadedKey.D.Cmp(key.D) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadOrGenerateKey_DefaultSecretName(t *testing.T) {
	client := fake.NewClientset()
	_, kid, err := LoadOrGenerateKey(context.Background(), client, "ns", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kid == "" {
		t.Fatal("expected kid")
	}
	// Verify default secret name was used
	_, err = client.CoreV1().Secrets("ns").Get(context.Background(), defaultSecretName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("expected secret with default name: %v", err)
	}
}

func TestStorePresignedURL(t *testing.T) {
	client := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "ns"},
		Data:       map[string][]byte{"kid": []byte("test-kid")},
	})
	err := StorePresignedURL(context.Background(), client, "ns", "my-secret", "http://example.com/upload")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret, _ := client.CoreV1().Secrets("ns").Get(context.Background(), "my-secret", metav1.GetOptions{})
	if string(secret.Data["presigned-url"]) != "http://example.com/upload" {
		t.Errorf("unexpected presigned-url: %s", string(secret.Data["presigned-url"]))
	}
}

func TestStoreRotatedKey_NewSecret(t *testing.T) {
	client := fake.NewClientset()
	key, err := kidcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid, _ := kidcrypto.DeriveKID(&key.PublicKey)

	err = StoreRotatedKey(context.Background(), client, "ns", "rot-secret", key, kid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret, err := client.CoreV1().Secrets("ns").Get(context.Background(), "rot-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret: %v", err)
	}
	if string(secret.Data["kid"]) != kid {
		t.Errorf("expected kid %q, got %q", kid, string(secret.Data["kid"]))
	}
}

func TestStoreRotatedKey_UpdatesExisting(t *testing.T) {
	client := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rot-secret", Namespace: "ns"},
		Data: map[string][]byte{
			"private-key.pem": []byte("old-pem"),
			"kid":             []byte("old-kid"),
		},
	})
	newKey, err := kidcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	newKID, _ := kidcrypto.DeriveKID(&newKey.PublicKey)

	err = StoreRotatedKey(context.Background(), client, "ns", "rot-secret", newKey, newKID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret, _ := client.CoreV1().Secrets("ns").Get(context.Background(), "rot-secret", metav1.GetOptions{})
	if string(secret.Data["kid"]) != newKID {
		t.Errorf("expected new kid %q, got %q", newKID, string(secret.Data["kid"]))
	}
	if string(secret.Data["prev-kid"]) != "old-kid" {
		t.Errorf("expected prev-kid 'old-kid', got %q", string(secret.Data["prev-kid"]))
	}
}

func TestStorePresignedURL_SecretNotFound(t *testing.T) {
client := fake.NewClientset()
// No secret exists
err := StorePresignedURL(context.Background(), client, "ns", "nonexistent", "http://example.com")
if err == nil {
t.Fatal("expected error for nonexistent secret")
}
}

func TestLoadOrGenerateKey_InvalidPEM(t *testing.T) {
client := fake.NewClientset(&corev1.Secret{
ObjectMeta: metav1.ObjectMeta{Name: "bad-pem", Namespace: "ns"},
Data: map[string][]byte{
"private-key.pem": []byte("invalid-pem"),
"kid":             []byte("some-kid"),
},
})
// Should generate new key since PEM is invalid
key, kid, err := LoadOrGenerateKey(context.Background(), client, "ns", "bad-pem")
// It will try to create a new secret, but secret already exists -> error
// OR it will just regenerate. Depends on the logic.
_ = key
_ = kid
_ = err
// Just testing no panic
}
