package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

const defaultMaxDedupEntries = 500000

type FindingDeduplicator struct {
	mu         sync.RWMutex
	seen       map[string]struct{}
	order      []string
	crossTask  bool
	maxEntries int
}

func NewFindingDeduplicator(crossTask bool) *FindingDeduplicator {
	return &FindingDeduplicator{
		seen:       make(map[string]struct{}),
		order:      make([]string, 0, 1024),
		crossTask:  crossTask,
		maxEntries: defaultMaxDedupEntries,
	}
}

func (d *FindingDeduplicator) IsDuplicate(taskID string, f *Finding) bool {
	fp := d.Fingerprint(taskID, f)
	d.mu.RLock()
	_, exists := d.seen[fp]
	d.mu.RUnlock()
	if exists {
		return true
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists = d.seen[fp]; exists {
		return true
	}
	if len(d.seen) >= d.maxEntries {
		d.evictOldest()
	}
	d.seen[fp] = struct{}{}
	d.order = append(d.order, fp)
	return false
}

func (d *FindingDeduplicator) evictOldest() {
	evictCount := len(d.order) / 4
	if evictCount == 0 {
		evictCount = 1
	}
	for i := 0; i < evictCount && i < len(d.order); i++ {
		delete(d.seen, d.order[i])
	}
	d.order = d.order[evictCount:]
}

func (d *FindingDeduplicator) Fingerprint(taskID string, f *Finding) string {
	var parts []string

	if !d.crossTask {
		parts = append(parts, taskID)
	}

	if f.Target != nil {
		parts = append(parts, f.Target.Host, f.Target.IP, fmt.Sprintf("%d", f.Target.Port))
	}
	parts = append(parts, f.ModuleID, f.Type, f.Title)

	if f.Data != nil {
		if param, ok := f.Data["param"]; ok {
			parts = append(parts, "p:"+param)
		}
		if via, ok := f.Data["inject_via"]; ok {
			parts = append(parts, "iv:"+via)
		}
	}

	raw := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:16])
}

func (d *FindingDeduplicator) DeduplicateFindings(taskID string, findings []*Finding) []*Finding {
	unique := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		if !d.IsDuplicate(taskID, f) {
			unique = append(unique, f)
		}
	}
	return unique
}

func (d *FindingDeduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}

func (d *FindingDeduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[string]struct{})
	d.order = d.order[:0]
}
