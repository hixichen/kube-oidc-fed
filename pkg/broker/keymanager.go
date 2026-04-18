package broker

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	kidcrypto "github.com/hixichen/kube-oidc-fed/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const defaultSecretName = "kube-oidc-fed-signing-key"

func LoadOrGenerateKey(ctx context.Context, client kubernetes.Interface, namespace, secretName string) (*ecdsa.PrivateKey, string, error) {
	if secretName == "" {
		secretName = defaultSecretName
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err == nil {
		pemData := secret.Data["private-key.pem"]
		kid := string(secret.Data["kid"])
		if len(pemData) > 0 && kid != "" {
			key, keyErr := kidcrypto.UnmarshalPrivateKeyPEM(pemData)
			if keyErr == nil {
				return key, kid, nil
			}
		}
	} else if !errors.IsNotFound(err) {
		return nil, "", fmt.Errorf("get secret: %w", err)
	}

	key, err := kidcrypto.GenerateKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	kid, err := kidcrypto.DeriveKID(&key.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("derive kid: %w", err)
	}
	pemData, err := kidcrypto.MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal key: %w", err)
	}
	secretObj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"private-key.pem": pemData,
			"kid":             []byte(kid),
		},
	}
	_, err = client.CoreV1().Secrets(namespace).Create(ctx, secretObj, metav1.CreateOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("create secret: %w", err)
	}
	return key, kid, nil
}

// StorePresignedURL stores the presigned URL in the K8s Secret for future reference.
func StorePresignedURL(ctx context.Context, client kubernetes.Interface, namespace, secretName, presignedURL string) error {
	if secretName == "" {
		secretName = defaultSecretName
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data["presigned-url"] = []byte(presignedURL)
	_, err = client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	return nil
}

// StoreRotatedKey stores a newly rotated key in the K8s Secret.
func StoreRotatedKey(ctx context.Context, client kubernetes.Interface, namespace, secretName string, key *ecdsa.PrivateKey, kid string) error {
	if secretName == "" {
		secretName = defaultSecretName
	}
	pemData, err := kidcrypto.MarshalPrivateKeyPEM(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get secret: %w", err)
		}
		secretObj := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
			},
			Data: map[string][]byte{
				"private-key.pem": pemData,
				"kid":             []byte(kid),
			},
		}
		_, err = client.CoreV1().Secrets(namespace).Create(ctx, secretObj, metav1.CreateOptions{})
		return err
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	// Keep old key for dual-key state
	secret.Data["prev-private-key.pem"] = secret.Data["private-key.pem"]
	secret.Data["prev-kid"] = secret.Data["kid"]
	secret.Data["private-key.pem"] = pemData
	secret.Data["kid"] = []byte(kid)
	_, err = client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}
