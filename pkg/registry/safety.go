package registry

import "fmt"

type SafetyConfig struct {
	MinKeyCount       int
	MaxRemovedPerOp   int
	MaxRemovedPercent float64
	AllowEmpty        bool
}

func DefaultSafetyConfig() SafetyConfig {
	return SafetyConfig{
		MinKeyCount:       0,
		MaxRemovedPerOp:   3,
		MaxRemovedPercent: 0.1,
		AllowEmpty:        false,
	}
}

func ValidateJWKSDelta(before, after int, cfg SafetyConfig) error {
	if after == 0 && !cfg.AllowEmpty {
		return fmt.Errorf("refusing to publish empty JWKS (AllowEmpty=false)")
	}
	if after < cfg.MinKeyCount {
		return fmt.Errorf("resulting JWKS would have %d keys, below minimum %d", after, cfg.MinKeyCount)
	}
	removed := before - after
	if removed < 0 {
		return nil
	}
	if removed > cfg.MaxRemovedPerOp {
		return fmt.Errorf("would remove %d keys, exceeds MaxRemovedPerOp=%d", removed, cfg.MaxRemovedPerOp)
	}
	if before > 0 {
		pct := float64(removed) / float64(before)
		if pct > cfg.MaxRemovedPercent {
			return fmt.Errorf("would remove %.0f%% of keys, exceeds MaxRemovedPercent=%.0f%%", pct*100, cfg.MaxRemovedPercent*100)
		}
	}
	return nil
}
