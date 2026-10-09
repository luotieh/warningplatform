// Package evidence computes traceable facts and separately schedules bounded
// semantic interpretation through an injected model, independently of storage.
package evidence

import "time"

type FactID string

const (
	BeaconPeriodic  FactID = "F_BEACON_PERIODIC"
	MultiDayPersist FactID = "F_MULTI_DAY_PERSIST"
	RuleVersion            = "evidence-algorithms-0.4"
)

type Scope struct {
	AssetID    string `json:"asset_id"`
	EndpointID string `json:"endpoint_id"`
	DeviceID   string `json:"device_id"`
	GroupID    string `json:"group_id,omitempty"`
}

// Scope must be resolved by the caller; the engine never guesses direction from IPs or IOC labels.
type Hit struct {
	ID         string    `json:"hit_id"`
	OccurredAt time.Time `json:"occurred_at"`
	Packets    *uint64   `json:"packets"`
	Scope      Scope     `json:"scope"`
}

type Coverage string

const (
	CoverageComplete Coverage = "complete"
	CoveragePartial  Coverage = "partial"
	CoverageUnknown  Coverage = "unknown"
)

type Quality struct {
	Coverage Coverage `json:"coverage"`
	// nil means truncation has not been verified, rather than false.
	CaptureTruncated *bool `json:"capture_truncated"`
}

type Request struct {
	EventID         string  `json:"event_id"`
	SnapshotVersion int64   `json:"snapshot_version"`
	Hits            []Hit   `json:"hits"`
	Quality         Quality `json:"quality"`
	// nil preserves the two inexpensive v0.1 defaults; all other facts require selection.
	// An explicit empty slice selects none. SupportedFacts lists all 59 registered facts.
	Facts  []FactID `json:"facts"`
	Inputs []Input  `json:"inputs,omitempty"`
	// AssetInputs aggregate already-bound hits across endpoints of one asset
	// and device. Only asset-wide rules run here; periodic rules stay endpoint-bound.
	AssetInputs []Input      `json:"asset_inputs,omitempty"`
	Groups      []GroupInput `json:"groups,omitempty"`
}

type Status string

const (
	Observed    Status = "observed"
	NotObserved Status = "not_observed"
	Missing     Status = "missing"
)

type ReasonCode string

const (
	NotRequested        ReasonCode = "not_requested"
	UnverifiedCoverage  ReasonCode = "unverified_coverage"
	InsufficientSamples ReasonCode = "insufficient_samples"
	MissingPackets      ReasonCode = "missing_packets"
	InvalidTime         ReasonCode = "missing_or_invalid_time"
	IncompleteNegative  ReasonCode = "incomplete_coverage_cannot_refute"
	ConditionsMet       ReasonCode = "conditions_met"
	ConditionsNotMet    ReasonCode = "conditions_not_met"
)

type Window struct {
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Convention string    `json:"convention"`
}

type Measurements struct {
	SampleCount           int                `json:"sample_count"`
	DaysActive            *int               `json:"days_active,omitempty"`
	IntervalCV            *float64           `json:"interval_cv,omitempty"`
	MedianIntervalSeconds *float64           `json:"median_interval_sec,omitempty"`
	MinIntervalSeconds    *float64           `json:"min_interval_sec,omitempty"`
	MaxIntervalSeconds    *float64           `json:"max_interval_sec,omitempty"`
	MaxPackets            *uint64            `json:"max_packets,omitempty"`
	Values                map[string]float64 `json:"values,omitempty"`
	Labels                []string           `json:"labels,omitempty"`
}

type Finding struct {
	FactID          FactID       `json:"fact_id"`
	RuleVersion     string       `json:"rule_version"`
	SnapshotVersion int64        `json:"snapshot_version"`
	Scope           Scope        `json:"scope"`
	Window          *Window      `json:"window"`
	Status          Status       `json:"status"`
	Eligibility     string       `json:"eligibility"`
	Quality         string       `json:"quality"`
	Measurements    Measurements `json:"measurements"`
	Parameters      Parameters   `json:"parameters"`
	SourceIDs       []string     `json:"source_ids"`
	ReasonCode      ReasonCode   `json:"reason_code"`
	Limitations     []string     `json:"limitations"`
	Dependencies    []Dependency `json:"dependencies,omitempty"`
}

type Dependency struct {
	Kind      string   `json:"kind"`
	Version   string   `json:"version"`
	SourceIDs []string `json:"source_ids"`
}

type Parameters struct {
	Periodic *PeriodicConfig    `json:"periodic,omitempty"`
	MultiDay *MultiDayConfig    `json:"multi_day,omitempty"`
	Values   map[string]float64 `json:"values,omitempty"`
}

const (
	MissingInput          ReasonCode = "missing_input"
	MissingBaseline       ReasonCode = "missing_or_unverified_baseline"
	MissingPolicy         ReasonCode = "missing_policy"
	UnresolvedBinding     ReasonCode = "unresolved_binding"
	StatisticalConstraint ReasonCode = "unsupported_statistical_input"
)

type Execution struct {
	FactID     FactID     `json:"fact_id"`
	Scope      Scope      `json:"scope"`
	Status     string     `json:"execution_status"`
	ReasonCode ReasonCode `json:"reason_code"`
}

type Result struct {
	EventID         string      `json:"event_id"`
	SnapshotVersion int64       `json:"snapshot_version"`
	RuleVersion     string      `json:"rule_version"`
	Findings        []Finding   `json:"algorithm_findings"`
	Executions      []Execution `json:"execution_plan"`
}
