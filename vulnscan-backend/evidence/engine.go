package evidence

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	_ "time/tzdata" // Keep Asia/Shanghai day buckets consistent on Windows and minimal containers.
)

// Engine is immutable after construction and safe for concurrent Evaluate calls.
type Engine struct {
	config      Config
	dayLocation *time.Location
}

func NewEngine(config Config) (*Engine, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	location, err := time.LoadLocation(config.MultiDay.Timezone)
	if err != nil {
		return nil, err
	}
	policies := make(map[FactID]map[string]float64)
	for id, values := range config.Policies {
		policies[id] = make(map[string]float64)
		for k, v := range values {
			policies[id][k] = v
		}
	}
	config.Policies = policies
	return &Engine{config: config, dayLocation: location}, nil
}

type observations struct {
	scope     Scope
	hits      []Hit
	sourceIDs []string
	complete  bool
	prepared  bool
	validTime bool
	times     []time.Time
	window    *Window
	input     *Input
	group     *GroupInput
	request   *Request
	hitIndex  map[string]Hit
}

// prepareTime is lazy and shared by selected algorithms within a scope.
func (g *observations) prepareTime() bool {
	if g.prepared {
		return g.validTime
	}
	g.prepared = true
	for _, hit := range g.hits {
		if hit.OccurredAt.IsZero() {
			return false
		}
		g.times = append(g.times, hit.OccurredAt.UTC())
	}
	sort.Slice(g.times, func(i, j int) bool { return g.times[i].Before(g.times[j]) })
	g.window = &Window{Start: g.times[0], End: g.times[len(g.times)-1], Convention: "observed_first_last_inclusive"}
	g.validTime = true
	return true
}

func (e *Engine) Evaluate(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(request.EventID) == "" || request.SnapshotVersion <= 0 || len(request.Hits) == 0 {
		return Result{}, fmt.Errorf("event_id, positive snapshot_version and nonempty hits are required")
	}
	if q := request.Quality.Coverage; q != "" && q != CoverageUnknown && q != CoverageComplete && q != CoveragePartial {
		return Result{}, fmt.Errorf("invalid coverage %q", q)
	}
	facts := request.Facts
	if facts == nil {
		facts = []FactID{BeaconPeriodic, MultiDayPersist}
	}
	selected := make(map[FactID]bool)
	for _, id := range facts {
		if !supported(id) {
			return Result{}, fmt.Errorf("unsupported fact %q", id)
		}
		if selected[id] {
			return Result{}, fmt.Errorf("duplicate requested fact %q", id)
		}
		selected[id] = true
	}
	complete := request.Quality.Coverage == CoverageComplete && request.Quality.CaptureTruncated != nil && !*request.Quality.CaptureTruncated
	groups := make(map[Scope]*observations)
	seen := make(map[string]bool)
	hitIndex := make(map[string]Hit, len(request.Hits))
	for _, hit := range request.Hits {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		hit.ID = strings.TrimSpace(hit.ID)
		if hit.ID == "" || seen[hit.ID] {
			return Result{}, fmt.Errorf("missing or duplicate hit_id %q", hit.ID)
		}
		seen[hit.ID] = true
		hit.Scope = Scope{AssetID: strings.TrimSpace(hit.Scope.AssetID), EndpointID: strings.TrimSpace(hit.Scope.EndpointID), DeviceID: strings.TrimSpace(hit.Scope.DeviceID)}
		if hit.Scope.AssetID == "" || hit.Scope.EndpointID == "" || hit.Scope.DeviceID == "" {
			return Result{}, fmt.Errorf("hit %q requires verified asset, endpoint and device identity", hit.ID)
		}
		hitIndex[hit.ID] = hit
		g := groups[hit.Scope]
		if g == nil {
			g = &observations{scope: hit.Scope, complete: complete, request: &request}
			groups[hit.Scope] = g
		}
		g.hits = append(g.hits, hit)
		g.sourceIDs = append(g.sourceIDs, hit.ID)
	}
	for i := range request.Inputs {
		input := &request.Inputs[i]
		g := groups[input.Scope]
		if g == nil || g.input != nil {
			return Result{}, fmt.Errorf("input scope is unknown or repeated: %+v", input.Scope)
		}
		g.input = input
	}
	assetScopes := map[Scope]bool{}
	assetBindings := map[string]bool{}
	for i := range request.AssetInputs {
		input := &request.AssetInputs[i]
		scope := input.Scope
		if scope.AssetID == "" || scope.DeviceID == "" || scope.EndpointID != "asset://"+scope.AssetID || scope.GroupID != "" || groups[scope] != nil || input.Window == nil || !input.Window.Start.Before(input.Window.End) {
			return Result{}, fmt.Errorf("invalid or repeated asset-wide scope: %+v", scope)
		}
		g := &observations{scope: scope, complete: complete, request: &request, input: input}
		for _, hit := range request.Hits {
			if hit.Scope.AssetID == scope.AssetID && hit.Scope.DeviceID == scope.DeviceID {
				if hit.OccurredAt.Before(input.Window.Start) || !hit.OccurredAt.Before(input.Window.End) {
					return Result{}, fmt.Errorf("asset-wide window excludes bound hit")
				}
				g.hits = append(g.hits, hit)
				g.sourceIDs = append(g.sourceIDs, hit.ID)
			}
		}
		if len(g.hits) == 0 {
			return Result{}, fmt.Errorf("asset-wide scope has no bound hits")
		}
		groups[scope] = g
		assetScopes[scope] = true
		assetBindings[scope.AssetID+"\x00"+scope.DeviceID] = true
	}
	scopes := make([]Scope, 0, len(groups))
	for scope := range groups {
		scopes = append(scopes, scope)
	}
	sort.Slice(scopes, func(i, j int) bool {
		a, b := scopes[i], scopes[j]
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		if a.EndpointID != b.EndpointID {
			return a.EndpointID < b.EndpointID
		}
		return a.DeviceID < b.DeviceID
	})
	result := Result{EventID: request.EventID, SnapshotVersion: request.SnapshotVersion, RuleVersion: RuleVersion, Findings: []Finding{}, Executions: []Execution{}}
	for _, scope := range scopes {
		g := groups[scope]
		sort.Strings(g.sourceIDs)
		for _, id := range SupportedFacts() {
			if assetScopes[scope] && !AssetWideFact(id) || !assetScopes[scope] && AssetWideFact(id) && assetBindings[scope.AssetID+"\x00"+scope.DeviceID] {
				continue
			}
			if groupRule(id) || (!selected[id] && id != BeaconPeriodic && id != MultiDayPersist) {
				continue
			}
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			execution := Execution{FactID: id, Scope: scope, Status: "skipped", ReasonCode: NotRequested}
			if selected[id] {
				var finding Finding
				if id == BeaconPeriodic {
					finding = e.periodic(g)
				} else if id == MultiDayPersist {
					finding = e.multiDay(g)
				} else {
					finding = e.additional(id, g)
				}
				finding.SnapshotVersion = request.SnapshotVersion
				execution.ReasonCode = finding.ReasonCode
				if finding.Eligibility == "eligible" || finding.ReasonCode == IncompleteNegative {
					execution.Status = "executed"
				}
				result.Findings = append(result.Findings, finding)
			}
			result.Executions = append(result.Executions, execution)
		}
	}
	groupIDs := map[string]bool{}
	for _, group := range request.Groups {
		if group.ID == "" || groupIDs[group.ID] {
			return Result{}, fmt.Errorf("missing or duplicate group_id")
		}
		groupIDs[group.ID] = true
	}
	for _, id := range SupportedFacts() {
		if !selected[id] || !groupRule(id) {
			continue
		}
		bound := request.Groups
		if len(bound) == 0 {
			bound = []GroupInput{{}}
		}
		for i := range bound {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			group := &bound[i]
			g := &observations{scope: Scope{GroupID: group.ID}, group: group, request: &request, complete: group.Complete, sourceIDs: append([]string(nil), group.SourceIDs...), hitIndex: hitIndex}
			for _, m := range group.Members {
				for _, hid := range m.HitIDs {
					if h, ok := hitIndex[hid]; ok {
						g.hits = append(g.hits, h)
					}
				}
			}
			finding := e.additional(id, g)
			finding.SnapshotVersion = request.SnapshotVersion
			status := "skipped"
			if finding.Eligibility == "eligible" {
				status = "executed"
			}
			result.Findings = append(result.Findings, finding)
			result.Executions = append(result.Executions, Execution{FactID: id, Scope: g.scope, Status: status, ReasonCode: finding.ReasonCode})
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return result, nil
}

func baseFinding(id FactID, g *observations, parameters Parameters, limits []string) Finding {
	quality := "complete"
	if !g.complete {
		quality = "coverage_gap"
	}
	return Finding{FactID: id, RuleVersion: RuleVersion, Scope: g.scope, Status: Missing,
		Eligibility: "ineligible", Quality: quality, Parameters: parameters,
		Measurements: Measurements{SampleCount: len(g.hits)},
		SourceIDs:    append([]string(nil), g.sourceIDs...), Limitations: limits}
}
