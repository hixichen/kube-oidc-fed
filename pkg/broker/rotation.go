package broker

import (
	"context"
	"time"

	"go.uber.org/zap"
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
	logger      *zap.Logger
	onRotate    func(ctx context.Context) error
}

func NewRotationManager(interval, gracePeriod time.Duration, logger *zap.Logger, onRotate func(ctx context.Context) error) *RotationManager {
	return &RotationManager{
		state:       StateStable,
		interval:    interval,
		gracePeriod: gracePeriod,
		logger:      logger,
		onRotate:    onRotate,
	}
}

func (rm *RotationManager) Start(ctx context.Context) {
	if rm.interval <= 0 {
		return // auto-rotation disabled
	}
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
	rm.logger.Info("starting key rotation", zap.String("state", string(rm.state)))
	rm.state = StateDualKey
	if rm.onRotate != nil {
		if err := rm.onRotate(ctx); err != nil {
			rm.logger.Error("rotation failed", zap.Error(err))
			rm.state = StateStable
			return
		}
	}
	rm.state = StateSwitched
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
