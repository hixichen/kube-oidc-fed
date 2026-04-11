package jwks

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
)

type JWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func PublicKeyToJWK(pub *ecdsa.PublicKey, kid string) (*JWK, error) {
	if pub == nil {
		return nil, fmt.Errorf("nil public key")
	}
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	// pad to 32 bytes for P-256
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)
	return &JWK{
		KeyType:   "EC",
		Curve:     "P-256",
		X:         base64.RawURLEncoding.EncodeToString(xPadded),
		Y:         base64.RawURLEncoding.EncodeToString(yPadded),
		KeyID:     kid,
		Algorithm: "ES256",
		Use:       "sig",
	}, nil
}

func BuildJWKS(keys []*JWK) *JWKS {
	result := &JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		if k != nil {
			result.Keys = append(result.Keys, *k)
		}
	}
	return result
}
