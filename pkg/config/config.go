package config

import (
	"time"
)

// BrokerConfig holds configuration for the broker.
type BrokerConfig struct {
	Issuer              string
	RegistryURL         string
	Audience            []string
	TokenTTL            time.Duration
	ClusterID           string
	Namespace           string
	SecretName          string
	AuthToken           string
	ListenAddr          string
	RotationInterval    time.Duration
	RotationGracePeriod time.Duration
	// JWT claim customization
	JWTSubjectTemplate string            // default: "system:serviceaccount:{{.Namespace}}:{{.ServiceAccount}}"
	JWTExtraClaims     map[string]string // additional static claims to inject into JWT
}

type RegistryConfig struct {
	ListenAddr      string
	S3Bucket        string
	S3Region        string
	S3Endpoint      string
	Issuer          string
	AuthToken       string
	MinKeyCount     int
	MaxRemovedPerOp int
	MaxRemovedPct   float64
	AllowEmpty      bool
}
