package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Store struct {
	client    *s3.Client
	presigner *s3.PresignClient
	bucket    string
}

func NewS3Store(client *s3.Client, bucket string) *S3Store {
	return &S3Store{
		client:    client,
		presigner: s3.NewPresignClient(client),
		bucket:    bucket,
	}
}

func (s *S3Store) PutKey(ctx context.Context, kid string, jwk []byte) error {
	key := "keys/" + kid + ".json"
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(jwk),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("s3 put key %s: %w", kid, err)
	}
	return nil
}

func (s *S3Store) GetKey(ctx context.Context, kid string) ([]byte, error) {
	key := "keys/" + kid + ".json"
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get key %s: %w", kid, err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *S3Store) DeleteKey(ctx context.Context, kid string) error {
	key := "keys/" + kid + ".json"
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3 delete key %s: %w", kid, err)
	}
	return nil
}

func (s *S3Store) ListKeys(ctx context.Context) ([]string, error) {
	out, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String("keys/"),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 list keys: %w", err)
	}
	var kids []string
	for _, obj := range out.Contents {
		k := aws.ToString(obj.Key)
		k = strings.TrimPrefix(k, "keys/")
		k = strings.TrimSuffix(k, ".json")
		if k != "" {
			kids = append(kids, k)
		}
	}
	return kids, nil
}

func (s *S3Store) PutJWKS(ctx context.Context, data []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(".well-known/jwks.json"),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("s3 put jwks: %w", err)
	}
	return nil
}

func (s *S3Store) GetJWKS(ctx context.Context) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(".well-known/jwks.json"),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get jwks: %w", err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *S3Store) PutDiscovery(ctx context.Context, data []byte) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(".well-known/openid-configuration"),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("s3 put discovery: %w", err)
	}
	return nil
}

func (s *S3Store) GetDiscovery(ctx context.Context) ([]byte, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(".well-known/openid-configuration"),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get discovery: %w", err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *S3Store) GeneratePresignedPutURL(ctx context.Context, kid string, ttl time.Duration) (string, error) {
	key := "keys/" + kid + ".json"
	req, err := s.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", fmt.Errorf("presign put %s: %w", kid, err)
	}
	return req.URL, nil
}
