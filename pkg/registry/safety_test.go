package registry

import "testing"

func TestValidateJWKSDelta_AllowEmpty(t *testing.T) {
cfg := SafetyConfig{AllowEmpty: true, MaxRemovedPerOp: 10, MaxRemovedPercent: 1.0}
if err := ValidateJWKSDelta(1, 0, cfg); err != nil {
t.Errorf("expected no error when AllowEmpty=true, got %v", err)
}
}

func TestValidateJWKSDelta_RefuseEmpty(t *testing.T) {
cfg := SafetyConfig{AllowEmpty: false, MaxRemovedPerOp: 10, MaxRemovedPercent: 1.0}
if err := ValidateJWKSDelta(1, 0, cfg); err == nil {
t.Error("expected error when AllowEmpty=false and result is 0 keys")
}
}

func TestValidateJWKSDelta_BelowMin(t *testing.T) {
cfg := SafetyConfig{AllowEmpty: true, MinKeyCount: 2, MaxRemovedPerOp: 10, MaxRemovedPercent: 1.0}
if err := ValidateJWKSDelta(3, 1, cfg); err == nil {
t.Error("expected error when below min key count")
}
}

func TestValidateJWKSDelta_ExceedsMaxRemovedPerOp(t *testing.T) {
cfg := SafetyConfig{AllowEmpty: true, MaxRemovedPerOp: 2, MaxRemovedPercent: 1.0}
if err := ValidateJWKSDelta(10, 7, cfg); err == nil {
t.Error("expected error when removing too many per op")
}
}

func TestValidateJWKSDelta_ExceedsMaxRemovedPct(t *testing.T) {
cfg := SafetyConfig{AllowEmpty: true, MaxRemovedPerOp: 100, MaxRemovedPercent: 0.1}
if err := ValidateJWKSDelta(10, 8, cfg); err == nil {
t.Error("expected error when removing too high percentage")
}
}

func TestValidateJWKSDelta_OK(t *testing.T) {
cfg := SafetyConfig{AllowEmpty: false, MinKeyCount: 1, MaxRemovedPerOp: 3, MaxRemovedPercent: 0.5}
if err := ValidateJWKSDelta(5, 4, cfg); err != nil {
t.Errorf("expected no error, got %v", err)
}
}

func TestValidateJWKSDelta_AddingKeys(t *testing.T) {
cfg := DefaultSafetyConfig()
if err := ValidateJWKSDelta(2, 3, cfg); err != nil {
t.Errorf("expected no error when adding keys, got %v", err)
}
}

func TestDefaultSafetyConfig(t *testing.T) {
cfg := DefaultSafetyConfig()
if cfg.MaxRemovedPerOp != 3 {
t.Errorf("expected MaxRemovedPerOp=3, got %d", cfg.MaxRemovedPerOp)
}
if cfg.MaxRemovedPercent != 0.1 {
t.Errorf("expected MaxRemovedPercent=0.1, got %f", cfg.MaxRemovedPercent)
}
}
