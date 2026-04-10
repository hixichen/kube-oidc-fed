package agent

import (
	"context"
	"log/slog"
	"time"
)

type RotationState string

const (
	StateStable   RotationState = "STABLE"
	StateDualKey  RotationState = "DUAL_KEY"
	StateSwitched RotationState = "SWITCHED"
	StateCleanup  RotationState = "CLEANUP"
)

type RotationManager struct {
	state       RotationState
	interval    time.Duration
	gracePeriod time.Duration
	logger      *slog.Logger
	onRotate    func(ctx context.Context) error
}

func NewRotationManager(interval, gracePeriod time.Duration, logger *slog.Logger, onRotate func(ctx context.Context) error) *RotationManager {
	return &RotationManager{
		state:       StateStable,
		interval:    interval,
		gracePeriod: gracePeriod,
		logger:      logger,
		onRotate:    onRotate,
	}
}

func (rm *RotationManager) Start(ctx context.Context) {
	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rm.rotate(ctx)
		}
	}
}

func (rm *RotationManager) rotate(ctx context.Context) {
	rm.logger.Info("starting key rotation", "state", rm.state)
	rm.state = StateDualKey
	if rm.onRotate != nil {
		if err := rm.onRotate(ctx); err != nil {
			rm.logger.Error("rotation failed", "err", err)
			rm.state = StateStable
			return
		}
	}
	rm.state = StateSwitched
	// Wait grace period then cleanup
	select {
	case <-ctx.Done():
		return
	case <-time.After(rm.gracePeriod):
	}
	rm.state = StateCleanup
	rm.state = StateStable
	rm.logger.Info("key rotation complete")
}

func (rm *RotationManager) State() RotationState {
	return rm.state
}
