package evidence

import (
	"fmt"
	"math"
)

type PeriodicConfig struct {
	MinSamples               int     `json:"min_samples"`
	MinIntervalSeconds       float64 `json:"min_interval_sec"`
	MaxIntervalSeconds       float64 `json:"max_interval_sec"`
	MaxIntervalCV            float64 `json:"max_interval_cv"`
	MaxPacketsPerObservation uint64  `json:"max_packets_per_observation"`
}

type MultiDayConfig struct {
	MinDays  int    `json:"min_days"`
	Timezone string `json:"timezone"`
}

type Config struct {
	Periodic PeriodicConfig
	MultiDay MultiDayConfig
	// Policies provide thresholds the source definition leaves unspecified.
	// Missing keys make the relevant rule ineligible; no fabricated baseline is used.
	Policies map[FactID]map[string]float64
}

// DefaultConfig matches the two implemented evidence-library v0.1 definitions.
// Adapters may load configuration elsewhere; the engine never reads files itself.
func DefaultConfig() Config {
	return Config{
		Periodic: PeriodicConfig{MinSamples: 8, MinIntervalSeconds: 5, MaxIntervalSeconds: 86400, MaxIntervalCV: 0.15, MaxPacketsPerObservation: 5},
		MultiDay: MultiDayConfig{MinDays: 2, Timezone: "Asia/Shanghai"},
	}
}

func (c Config) validate() error {
	p := c.Periodic
	finite := func(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
	if p.MinSamples < 2 || !finite(p.MinIntervalSeconds) || !finite(p.MaxIntervalSeconds) || !finite(p.MaxIntervalCV) || p.MinIntervalSeconds <= 0 || p.MaxIntervalSeconds < p.MinIntervalSeconds || p.MaxIntervalCV < 0 {
		return fmt.Errorf("invalid periodic configuration")
	}
	if c.MultiDay.MinDays < 2 || c.MultiDay.Timezone != "Asia/Shanghai" {
		return fmt.Errorf("multi-day requires min_days >= 2 and Asia/Shanghai")
	}
	for id, values := range c.Policies {
		if !supported(id) {
			return fmt.Errorf("unknown policy fact %q", id)
		}
		for name, value := range values {
			if !finite(value) || !validPolicy(id, name, value) {
				return fmt.Errorf("invalid policy %s/%s", id, name)
			}
		}
	}
	return nil
}

func validPolicy(id FactID, name string, value float64) bool {
	allowed := map[FactID][]string{
		"F_BEACON_JITTER": {"ljung_box_lags", "median_relative_tolerance"}, "F_RATE_RAMP": {"window_seconds"},
		"F_FAILED_TO_ACTIVE": {"min_failures"}, "F_BRAND_IMPOSTOR": {"max_edit_distance"},
		"F_PORT_SEQUENCE": {"difference_entropy_threshold"}, "F_SMALL_PACKET": {"small_payload_bytes"},
		"F_MULTI_ASSET_IOC": {"cluster_window_seconds"}, "F_MULTI_ASSET_DIST": {"subnet_entropy_min"},
		"F_TIME_COORDINATION": {"bucket_seconds", "max_lag_bins"}, "F_COORD_FANOUT": {"handoff_seconds"},
		"F_INFECTION_CHAIN": {"chain_window_seconds"}, "F_COORD_PATTERN_RECURRENCE": {"bucket_seconds"},
		"F_HIST_SCHEDULE_MATCH": {"kl_threshold"}, "F_HIST_COORD_PARAM_MATCH": {"parameter_relative_tolerance"},
	}
	ok := false
	for _, k := range allowed[id] {
		if k == name {
			ok = true
		}
	}
	if !ok || value < 0 {
		return false
	}
	switch name {
	case "ljung_box_lags", "max_edit_distance":
		return value >= 1 && value == math.Trunc(value)
	case "min_failures":
		return value >= 2 && value == math.Trunc(value)
	case "max_lag_bins":
		return value == math.Trunc(value) && value <= 64
	case "window_seconds", "small_payload_bytes", "cluster_window_seconds", "bucket_seconds", "chain_window_seconds", "difference_entropy_threshold":
		return value > 0
	}
	return true
}
