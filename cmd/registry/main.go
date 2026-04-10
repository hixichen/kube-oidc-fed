package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hixichen/kube-kidring/pkg/config"
	"github.com/hixichen/kube-kidring/pkg/registry"
	kidstore "github.com/hixichen/kube-kidring/pkg/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := &config.RegistryConfig{}
	flag.StringVar(&cfg.ListenAddr, "listen-addr", envOrDefault("REGISTRY_LISTEN_ADDR", ":8080"), "Listen address")
	flag.StringVar(&cfg.S3Bucket, "s3-bucket", os.Getenv("REGISTRY_S3_BUCKET"), "S3 bucket")
	flag.StringVar(&cfg.S3Region, "s3-region", envOrDefault("REGISTRY_S3_REGION", "us-east-1"), "S3 region")
	flag.StringVar(&cfg.S3Endpoint, "s3-endpoint", os.Getenv("REGISTRY_S3_ENDPOINT"), "S3 endpoint (for MinIO)")
	flag.StringVar(&cfg.Issuer, "issuer", os.Getenv("REGISTRY_ISSUER"), "OIDC issuer URL")
	flag.StringVar(&cfg.AuthToken, "auth-token", os.Getenv("REGISTRY_AUTH_TOKEN"), "Auth token")
	useMemory := flag.Bool("memory", false, "Use in-memory store")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var st kidstore.Store
	if *useMemory || cfg.S3Bucket == "" {
		logger.Info("using in-memory store")
		st = kidstore.NewMemoryStore()
	} else {
		s3Client, err := newS3Client(ctx, cfg)
		if err != nil {
			logger.Error("failed to create S3 client", "err", err)
			os.Exit(1)
		}
		st = kidstore.NewS3Store(s3Client, cfg.S3Bucket)
	}

	safety := registry.SafetyConfig{
		MinKeyCount:       cfg.MinKeyCount,
		MaxRemovedPerOp:   cfg.MaxRemovedPerOp,
		MaxRemovedPercent: cfg.MaxRemovedPct,
		AllowEmpty:        cfg.AllowEmpty,
	}
	if safety.MaxRemovedPerOp == 0 {
		safety.MaxRemovedPerOp = 3
	}
	if safety.MaxRemovedPercent == 0 {
		safety.MaxRemovedPercent = 0.1
	}

	reg := registry.New(st, cfg.Issuer, logger, safety)
	if err := reg.Initialize(ctx); err != nil {
		logger.Error("registry initialization failed", "err", err)
		os.Exit(1)
	}

	handler := registry.NewHandler(reg, cfg.AuthToken, logger)
	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
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

	logger.Info("registry starting", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

func newS3Client(ctx context.Context, cfg *config.RegistryConfig) (*s3.Client, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.S3Region),
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	s3Opts := []func(*s3.Options){}
	if cfg.S3Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3Endpoint)
			o.UsePathStyle = true
		})
	}
	return s3.NewFromConfig(awsCfg, s3Opts...), nil
}

func envOrDefault(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return def
}
