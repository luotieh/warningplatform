package nuclei

import (
	"log/slog"
	"sync"
)

// TemplateDedup tracks which PoC templates have already been executed
// for a given task+target combination, preventing redundant execution.
type TemplateDedup struct {
	mu       sync.RWMutex
	executed map[string]map[string]struct{} // taskID -> set of "pocID:target" keys
}

var (
	globalTemplateDedup     *TemplateDedup
	globalTemplateDedupOnce sync.Once
)

func GetGlobalTemplateDedup() *TemplateDedup {
	globalTemplateDedupOnce.Do(func() {
		globalTemplateDedup = NewTemplateDedup()
	})
	return globalTemplateDedup
}

func NewTemplateDedup() *TemplateDedup {
	return &TemplateDedup{
		executed: make(map[string]map[string]struct{}),
	}
}

// RecordExecution marks a template as having been executed against targets.
func (td *TemplateDedup) RecordExecution(taskID string, pocIDs []string, targets []string) {
	td.mu.Lock()
	defer td.mu.Unlock()

	if _, ok := td.executed[taskID]; !ok {
		td.executed[taskID] = make(map[string]struct{})
	}

	for _, pocID := range pocIDs {
		for _, target := range targets {
			key := pocID + ":" + target
			td.executed[taskID][key] = struct{}{}
		}
	}
}

// FilterUnexecuted filters out PoC templates that have already been executed
// for the given task and targets. Returns only templates not yet run.
func (td *TemplateDedup) FilterUnexecuted(taskID string, templates []*PocEntry, targets []string) []*PocEntry {
	td.mu.RLock()
	defer td.mu.RUnlock()

	taskExecuted, ok := td.executed[taskID]
	if !ok || len(taskExecuted) == 0 {
		return templates
	}

	var filtered []*PocEntry
	var skipped int

	for _, t := range templates {
		allExecuted := true
		for _, target := range targets {
			key := t.ID + ":" + target
			if _, done := taskExecuted[key]; !done {
				allExecuted = false
				break
			}
		}
		if allExecuted && len(targets) > 0 {
			skipped++
		} else {
			filtered = append(filtered, t)
		}
	}

	if skipped > 0 {
		slog.Info("[TemplateDedup] 跳过已执行的 PoC 模板",
			"task_id", taskID,
			"skipped", skipped,
			"remaining", len(filtered),
		)
	}

	return filtered
}

// CleanupTask removes all tracking data for a completed task.
func (td *TemplateDedup) CleanupTask(taskID string) {
	td.mu.Lock()
	delete(td.executed, taskID)
	td.mu.Unlock()
}
