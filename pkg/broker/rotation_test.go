package broker

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRotationManagerDisabled(t *testing.T) {
	called := false
	rm := NewRotationManager(0, time.Minute, zap.NewNop(), func(ctx context.Context) error {
		called = true
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rm.Start(ctx) // should return immediately because interval == 0
	if called {
		t.Fatal("onRotate should not be called when interval is 0")
	}
}

func TestRotationManagerState(t *testing.T) {
	rm := NewRotationManager(50*time.Millisecond, 10*time.Millisecond, zap.NewNop(), nil)
	if rm.State() != StateStable {
		t.Fatalf("expected STABLE, got %s", rm.State())
	}
}

func TestRotationManagerRotates(t *testing.T) {
	rotateCh := make(chan struct{}, 1)
	rm := NewRotationManager(50*time.Millisecond, 10*time.Millisecond, zap.NewNop(), func(ctx context.Context) error {
		rotateCh <- struct{}{}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go rm.Start(ctx)
	select {
	case <-rotateCh:
		// rotation happened
	case <-time.After(400*time.Millisecond):
		t.Fatal("rotation did not happen within timeout")
	}
}

func TestRotationManagerRotateError(t *testing.T) {
	rm := &RotationManager{
		state:       StateStable,
		gracePeriod: 10 * time.Millisecond,
		logger:      zap.NewNop(),
		onRotate: func(ctx context.Context) error {
			return context.Canceled
		},
	}
	ctx := context.Background()
	rm.rotate(ctx)
	if rm.State() != StateStable {
		t.Fatalf("expected STABLE after error, got %s", rm.State())
	}
}
