package main

import (
"context"
"net/http"
"os"
"os/signal"
"strings"
"syscall"
"time"

"github.com/aws/aws-sdk-go-v2/aws"
awsconfig "github.com/aws/aws-sdk-go-v2/config"
"github.com/aws/aws-sdk-go-v2/service/s3"
"github.com/hixichen/kube-kidring/pkg/config"
"github.com/hixichen/kube-kidring/pkg/registry"
kidstore "github.com/hixichen/kube-kidring/pkg/store"
"github.com/spf13/pflag"
"github.com/spf13/viper"
"go.uber.org/zap"
)

func main() {
logger, _ := zap.NewProduction()
defer logger.Sync()

pflag.String("config", "", "Path to YAML config file")
pflag.String("listen-addr", ":8080", "Listen address")
pflag.String("s3-bucket", "", "S3 bucket")
pflag.String("s3-region", "us-east-1", "S3 region")
pflag.String("s3-endpoint", "", "S3 endpoint (for MinIO)")
pflag.String("issuer", "", "OIDC issuer URL")
pflag.String("auth-token", "", "Auth token")
pflag.Bool("memory", false, "Use in-memory store")
pflag.Parse()

v := viper.New()
v.SetEnvPrefix("REGISTRY")
v.AutomaticEnv()
v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
v.BindPFlags(pflag.CommandLine)

if cfgFile := v.GetString("config"); cfgFile != "" {
v.SetConfigFile(cfgFile)
if err := v.ReadInConfig(); err != nil {
logger.Warn("failed to read config file", zap.String("file", cfgFile), zap.Error(err))
}
}

cfg := &config.RegistryConfig{
ListenAddr: v.GetString("listen-addr"),
S3Bucket:   v.GetString("s3-bucket"),
S3Region:   v.GetString("s3-region"),
S3Endpoint: v.GetString("s3-endpoint"),
Issuer:     v.GetString("issuer"),
AuthToken:  v.GetString("auth-token"),
}
useMemory := v.GetBool("memory")

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

var st kidstore.Store
if useMemory || cfg.S3Bucket == "" {
logger.Info("using in-memory store")
st = kidstore.NewMemoryStore()
} else {
s3Client, err := newS3Client(ctx, cfg)
if err != nil {
logger.Error("failed to create S3 client", zap.Error(err))
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
logger.Error("registry initialization failed", zap.Error(err))
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
srv.Shutdown(shutdownCtx)
}()

logger.Info("registry starting", zap.String("addr", cfg.ListenAddr))
if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
logger.Error("server error", zap.Error(err))
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
