package agent

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	kidcrypto "github.com/hixichen/kube-kidring/pkg/crypto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const defaultSecretName = "kidring-signing-key"

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

	// Generate new key
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
