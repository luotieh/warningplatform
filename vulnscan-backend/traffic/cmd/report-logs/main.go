// Report log maintenance and cohort summary. No database or model calls.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
	"vulnscan-backend/traffic/internal/service"
)

func main() {
	root := flag.String("root", "data/repLogs", "report log root")
	prune := flag.Int("prune-days", 0, "explicitly delete finished runs older than N days; 0 disables deletion")
	flag.Parse()
	if *prune > 0 {
		n, e := service.PruneReportLogs(*root, *prune, time.Now())
		if e != nil {
			fail(e)
		}
		fmt.Printf("removed_finished_runs=%d\n", n)
		return
	}
	latest := map[string]map[string]any{}
	err := filepath.WalkDir(*root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.Name() != "manifest.json" {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var meta map[string]any
		if json.Unmarshal(raw, &meta) != nil {
			return nil
		}
		id, _ := meta["event_id"].(string)
		date, _ := meta["started_at"].(string)
		if id == "" {
			return nil
		}
		previous := latest[id]
		if previous != nil {
			previousDate, _ := time.Parse(time.RFC3339Nano, previous["started_at"].(string))
			candidateDate, _ := time.Parse(time.RFC3339Nano, date)
			if !candidateDate.After(previousDate) {
				return nil
			}
		}
		meta["started_at"] = date
		meta["run_directory"] = filepath.Dir(path)
		latest[id] = meta
		return nil
	})
	if err != nil {
		fail(err)
	}
	rows := []map[string]any{}
	facts, slots, gapFree := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ids := []string{}
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		meta := latest[id]
		row := map[string]any{"event_id": id, "manifest": meta}
		raw, e := os.ReadFile(filepath.Join(meta["run_directory"].(string), "material-coverage.json"))
		if e == nil {
			var a map[string]any
			if json.Unmarshal(raw, &a) == nil {
				row["coverage"] = a
				union(facts, a["completed_fact_ids"])
				union(slots, a["validated_semantic_slot_ids"])
				union(gapFree, a["gap_free_fact_ids"])
			}
		}
		rows = append(rows, row)
	}
	out := map[string]any{"event_count": len(rows), "selection": "latest logged run per event; inspect task type and completion status", "events": rows, "completed_fact_type_union": keys(facts), "validated_semantic_slot_type_union": keys(slots), "completed_fact_type_union_count": len(facts), "validated_semantic_slot_type_union_count": len(slots), "gap_free_fact_type_union": keys(gapFree), "gap_free_fact_type_union_count": len(gapFree), "note": "completed negative findings count as computations, not malicious evidence; read-only plans do not establish semantic execution; missing does not prove not applicable"}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(out); e != nil {
		fail(e)
	}
}
func union(out map[string]bool, v any) {
	if m, ok := v.(map[string]any); ok {
		for k, v := range m {
			if v == true {
				out[k] = true
			}
		}
	}
}
func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
