package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hixichen/kube-kidring/pkg/broker"
	"github.com/hixichen/kube-kidring/pkg/config"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	pflag.String("config", "", "Path to YAML config file")
	pflag.String("issuer", "", "OIDC issuer URL")
	pflag.String("registry-url", "", "Registry URL")
	pflag.String("cluster-id", "", "Cluster ID")
	pflag.String("namespace", "kidring", "Namespace")
	pflag.String("secret-name", "kidring-signing-key", "Secret name")
	pflag.String("auth-token", "", "Auth token for registry")
	pflag.String("listen-addr", ":8080", "Listen address")
	pflag.String("audience", "", "Comma-separated audiences")
	pflag.Duration("token-ttl", time.Hour, "Token TTL")
	pflag.Duration("rotation-interval", 24*time.Hour, "Rotation interval")
	pflag.Duration("rotation-grace", time.Hour, "Rotation grace period")
	pflag.String("jwt-subject-template", "", "JWT subject template")
	pflag.String("jwt-extra-claims", "", "Comma-separated key=value extra JWT claims")
	pflag.Parse()

	v := viper.New()
	v.SetEnvPrefix("BROKER")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.BindPFlags(pflag.CommandLine)

	if cfgFile := v.GetString("config"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			logger.Warn("failed to read config file", zap.String("file", cfgFile), zap.Error(err))
		}
	}

	cfg := &config.BrokerConfig{
		Issuer:              v.GetString("issuer"),
		RegistryURL:         v.GetString("registry-url"),
		ClusterID:           v.GetString("cluster-id"),
		Namespace:           v.GetString("namespace"),
		SecretName:          v.GetString("secret-name"),
		AuthToken:           v.GetString("auth-token"),
		ListenAddr:          v.GetString("listen-addr"),
		TokenTTL:            v.GetDuration("token-ttl"),
		RotationInterval:    v.GetDuration("rotation-interval"),
		RotationGracePeriod: v.GetDuration("rotation-grace"),
		JWTSubjectTemplate:  v.GetString("jwt-subject-template"),
	}

	audienceStr := v.GetString("audience")
	if audienceStr != "" {
		cfg.Audience = strings.Split(audienceStr, ",")
	}

	extraClaimsStr := v.GetString("jwt-extra-claims")
	if extraClaimsStr != "" {
		cfg.JWTExtraClaims = make(map[string]string)
		for _, pair := range strings.Split(extraClaimsStr, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				cfg.JWTExtraClaims[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	k8sClient, err := newK8sClient()
	if err != nil {
		logger.Error("failed to create k8s client", zap.Error(err))
		os.Exit(1)
	}

	b := broker.NewBroker(cfg, k8sClient, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := b.Initialize(ctx); err != nil {
		logger.Error("broker initialization failed", zap.Error(err))
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: b.HTTPHandler(),
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		logger.Info("shutting down")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	logger.Info("broker starting", zap.String("addr", cfg.ListenAddr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", zap.Error(err))
		os.Exit(1)
	}
}

func newK8sClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home := os.Getenv("HOME")
			kubeconfig = home + "/.kube/config"
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(cfg)
}
