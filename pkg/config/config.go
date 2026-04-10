package config

import (
	"time"
)

type AgentConfig struct {
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
