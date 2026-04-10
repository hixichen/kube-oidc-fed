package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hixichen/kube-kidring/pkg/agent"
	"github.com/hixichen/kube-kidring/pkg/config"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := &config.AgentConfig{}
	flag.StringVar(&cfg.Issuer, "issuer", os.Getenv("AGENT_ISSUER"), "OIDC issuer URL")
	flag.StringVar(&cfg.RegistryURL, "registry-url", os.Getenv("AGENT_REGISTRY_URL"), "Registry URL")
	flag.StringVar(&cfg.ClusterID, "cluster-id", os.Getenv("AGENT_CLUSTER_ID"), "Cluster ID")
	flag.StringVar(&cfg.Namespace, "namespace", envOrDefault("AGENT_NAMESPACE", "kidring"), "Namespace")
	flag.StringVar(&cfg.SecretName, "secret-name", envOrDefault("AGENT_SECRET_NAME", "kidring-signing-key"), "Secret name")
	flag.StringVar(&cfg.AuthToken, "auth-token", os.Getenv("AGENT_AUTH_TOKEN"), "Auth token for registry")
	flag.StringVar(&cfg.ListenAddr, "listen-addr", envOrDefault("AGENT_LISTEN_ADDR", ":8080"), "Listen address")
	audienceStr := flag.String("audience", os.Getenv("AGENT_AUDIENCE"), "Comma-separated audiences")
	tokenTTL := flag.Duration("token-ttl", durationOrDefault("AGENT_TOKEN_TTL", time.Hour), "Token TTL")
	rotInterval := flag.Duration("rotation-interval", durationOrDefault("AGENT_ROTATION_INTERVAL", 24*time.Hour), "Rotation interval")
	rotGrace := flag.Duration("rotation-grace", durationOrDefault("AGENT_ROTATION_GRACE", time.Hour), "Rotation grace period")
	flag.Parse()

	cfg.TokenTTL = *tokenTTL
	cfg.RotationInterval = *rotInterval
	cfg.RotationGracePeriod = *rotGrace
	if *audienceStr != "" {
		cfg.Audience = strings.Split(*audienceStr, ",")
	}

	k8sClient, err := newK8sClient()
	if err != nil {
		logger.Error("failed to create k8s client", "err", err)
		os.Exit(1)
	}

	a := agent.NewAgent(cfg, k8sClient, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Initialize(ctx); err != nil {
		logger.Error("agent initialization failed", "err", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: a.HTTPHandler(),
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		logger.Info("shutting down")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("agent starting", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "err", err)
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

func envOrDefault(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}

func durationOrDefault(env string, def time.Duration) time.Duration {
	if v := os.Getenv(env); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}
