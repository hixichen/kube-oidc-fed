package crypto

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ClusterID string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
}

func SignToken(key *ecdsa.PrivateKey, kid string, claims Claims) (string, error) {
	mapClaims := jwt.MapClaims{
		"iss":        claims.Issuer,
		"sub":        claims.Subject,
		"aud":        claims.Audience,
		"cluster_id": claims.ClusterID,
		"exp":        claims.ExpiresAt.Unix(),
		"iat":        claims.IssuedAt.Unix(),
		"nbf":        claims.NotBefore.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, mapClaims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}
