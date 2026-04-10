package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"go.uber.org/zap"
)

type registrarRequest struct {
	KID string          `json:"kid"`
	JWK json.RawMessage `json:"jwk"`
}

type registrarResponse struct {
	UploadURL string `json:"upload_url"`
}

type reissueResponse struct {
	UploadURL string `json:"upload_url"`
}

// RegisterKey registers a key with the registry and returns the presigned upload URL.
func RegisterKey(ctx context.Context, registryURL, authToken, kid string, jwk []byte, logger *zap.Logger) (string, error) {
	reqBody := registrarRequest{KID: kid, JWK: json.RawMessage(jwk)}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal register request: %w", err)
	}

	var uploadURL string
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "POST", registryURL+"/register", bytes.NewReader(bodyBytes))
		if err != nil {
			return "", fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Warn("register attempt failed", zap.Int("attempt", attempt+1), zap.Error(err))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			logger.Warn("register returned non-200", zap.Int("attempt", attempt+1), zap.Int("status", resp.StatusCode))
			continue
		}
		var regResp registrarResponse
		if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
			resp.Body.Close()
			logger.Warn("decode register response failed", zap.Int("attempt", attempt+1), zap.Error(err))
			continue
		}
		resp.Body.Close()
		uploadURL = regResp.UploadURL
		break
	}
	if uploadURL == "" {
		return "", fmt.Errorf("failed to register key after retries")
	}

	// PUT JWK to presigned URL
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(jwk))
		if err != nil {
			return "", fmt.Errorf("create upload request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			logger.Warn("upload attempt failed", zap.Int("attempt", attempt+1), zap.Error(err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return uploadURL, nil
		}
		logger.Warn("upload returned non-2xx", zap.Int("attempt", attempt+1), zap.Int("status", resp.StatusCode))
	}
	return "", fmt.Errorf("failed to upload key after retries")
}

// ReissuePresignedURL calls the registry to reissue a presigned URL for an existing kid.
func ReissuePresignedURL(ctx context.Context, registryURL, authToken, kid string, logger *zap.Logger) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", registryURL+"/reissue/"+kid, nil)
	if err != nil {
		return "", fmt.Errorf("create reissue request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("reissue request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("reissue returned %d", resp.StatusCode)
	}
	var r reissueResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("decode reissue response: %w", err)
	}
	return r.UploadURL, nil
}
