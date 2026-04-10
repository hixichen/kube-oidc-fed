package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"
)

type registrarRequest struct {
	KID string          `json:"kid"`
	JWK json.RawMessage `json:"jwk"`
}

type registrarResponse struct {
	UploadURL string `json:"upload_url"`
}

func RegisterKey(ctx context.Context, registryURL, authToken, kid string, jwk []byte) error {
	logger := slog.Default()
	reqBody := registrarRequest{KID: kid, JWK: json.RawMessage(jwk)}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	var uploadURL string
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "POST", registryURL+"/register", bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Warn("register attempt failed", "attempt", attempt+1, "err", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			logger.Warn("register returned non-200", "attempt", attempt+1, "status", resp.StatusCode)
			continue
		}
		var regResp registrarResponse
		if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
			resp.Body.Close()
			logger.Warn("decode register response failed", "attempt", attempt+1, "err", err)
			continue
		}
		resp.Body.Close()
		uploadURL = regResp.UploadURL
		break
	}
	if uploadURL == "" {
		return fmt.Errorf("failed to register key after retries")
	}

	// PUT to presigned URL
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(jwk))
		if err != nil {
			return fmt.Errorf("create upload request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Warn("upload attempt failed", "attempt", attempt+1, "err", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		logger.Warn("upload returned non-2xx", "attempt", attempt+1, "status", resp.StatusCode)
	}
	return fmt.Errorf("failed to upload key after retries")
}
