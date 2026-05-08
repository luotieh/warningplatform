package engine

import (
	"log/slog"
	"sort"
	"sync"
)

type ModulePrioritizer struct {
	mu     sync.RWMutex
	scores map[string]*moduleScore
}

type moduleScore struct {
	findingCount  int
	targetCount   int
	avgDurationMs float64
	successRate   float64
	priority      float64
}

func NewModulePrioritizer() *ModulePrioritizer {
	return &ModulePrioritizer{
		scores: make(map[string]*moduleScore),
	}
}

func (mp *ModulePrioritizer) RecordResult(moduleID string, findings int, newTargets int, durationMs float64, success bool) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	s, ok := mp.scores[moduleID]
	if !ok {
		s = &moduleScore{successRate: 1.0}
		mp.scores[moduleID] = s
	}

	s.findingCount += findings
	s.targetCount += newTargets

	if s.avgDurationMs == 0 {
		s.avgDurationMs = durationMs
	} else {
		s.avgDurationMs = s.avgDurationMs*0.7 + durationMs*0.3
	}

	if success {
		s.successRate = s.successRate*0.8 + 0.2
	} else {
		s.successRate = s.successRate*0.8 + 0.0
	}

	s.priority = calculatePriority(s)
}

func calculatePriority(s *moduleScore) float64 {
	findingScore := float64(s.findingCount) * 3.0
	targetScore := float64(s.targetCount) * 2.0
	speedScore := 0.0
	if s.avgDurationMs > 0 {
		speedScore = 1000.0 / s.avgDurationMs
	}
	reliabilityScore := s.successRate * 10.0

	return findingScore + targetScore + speedScore + reliabilityScore
}

func (mp *ModulePrioritizer) SortModules(modules []ScanModule) []ScanModule {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if len(mp.scores) == 0 {
		return modules
	}

	sorted := make([]ScanModule, len(modules))
	copy(sorted, modules)

	sort.SliceStable(sorted, func(i, j int) bool {
		si := mp.getScore(sorted[i].ID())
		sj := mp.getScore(sorted[j].ID())
		return si > sj
	})

	ids := make([]string, len(sorted))
	for i, m := range sorted {
		ids[i] = m.ID()
	}
	slog.Debug("[Priority] 模块排序", "order", ids)

	return sorted
}

func (mp *ModulePrioritizer) getScore(moduleID string) float64 {
	if s, ok := mp.scores[moduleID]; ok {
		return s.priority
	}
	return 0
}

func (mp *ModulePrioritizer) Stats() map[string]interface{} {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	result := make(map[string]interface{})
	for id, s := range mp.scores {
		result[id] = map[string]interface{}{
			"findings":     s.findingCount,
			"targets":      s.targetCount,
			"avg_ms":       int(s.avgDurationMs),
			"success_rate": int(s.successRate * 100),
			"priority":     int(s.priority),
		}
	}
	return result
}
