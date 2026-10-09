// evidence-check validates real database snapshots without LLM calls or writes.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"vulnscan-backend/traffic/internal/config"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func main() {
	event := flag.String("event", "", "validate one real event ID")
	sample := flag.Int("sample", 10, "maximum snapshot records to sample, 1..100 (record-key order)")
	output := flag.String("output", "", "save JSON results to this local path")
	importPath := flag.String("import-sources", "", "explicitly replace the trusted source registry from an audited JSON file")
	flag.Parse()
	if *sample < 1 || *sample > 100 {
		fail("sample must be 1..100")
	}
	cfg := config.Load()
	settings := config.SettingsFromStoreConfig(cfg)
	if cfg.StoreBackend != "mysql" || cfg.DatabaseURL == "" {
		fail("mysql configuration is required; no test data fallback")
	}
	db, err := sql.Open("mysql", cfg.DatabaseURL)
	if err != nil {
		fail("database configuration invalid")
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if db.PingContext(ctx) != nil {
		fail("database connection unavailable")
	}
	svc := service.Services{Store: store.NewMySQLStore(db)}
	if *importPath != "" {
		f, err := os.Open(*importPath)
		if err != nil {
			fail("source file unavailable")
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || info.Size() > 2<<20 {
			fail("source file budget exceeded")
		}
		raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
		if err != nil {
			fail("source file unavailable")
		}
		if err = svc.ImportEvidenceSources(ctx, raw); err != nil {
			fail("trusted source import rejected; check audit, provenance, binding and database availability")
		}
		fmt.Println("trusted source registry imported")
		return
	}
	ids := []string{}
	if *event != "" {
		ids = append(ids, *event)
	} else {
		records, err := svc.Store.AggregateRecords(ctx, "snapshot", "", *sample)
		if err != nil {
			fail("snapshot sample query failed")
		}
		seen := map[string]bool{}
		for _, r := range records {
			var snap service.EvidenceSnapshot
			if json.Unmarshal(r.Value, &snap) != nil || snap.EventID == "" {
				fail("snapshot sample contains invalid record")
			}
			if !seen[snap.EventID] {
				ids = append(ids, snap.EventID)
				seen[snap.EventID] = true
			}
		}
		if len(ids) == 0 {
			rows, err := db.QueryContext(ctx, "SELECT event_id FROM events ORDER BY id DESC LIMIT ?", *sample)
			if err != nil {
				fail("legacy event sample query failed")
			}
			for rows.Next() {
				var id string
				if rows.Scan(&id) != nil {
					rows.Close()
					fail("legacy event sample invalid")
				}
				ids = append(ids, id)
			}
			if rows.Err() != nil {
				rows.Close()
				fail("legacy event sample failed")
			}
			rows.Close()
		}
	}
	results := []service.EvidenceValidation{}
	for _, id := range ids {
		r, err := svc.ValidateReportEvidence(ctx, id)
		if err != nil {
			fail("validation failed; inspect typed service diagnostics")
		}
		results = append(results, r)
	}
	// Bounded inventory distinguishes an empty sample from successful real
	// event acceptance. EXISTS probes use indexed limits, never COUNT(full table).
	inventory := map[string]bool{}
	for name, query := range map[string]string{"events_present": "SELECT EXISTS(SELECT 1 FROM events LIMIT 1)", "hits_present": "SELECT EXISTS(SELECT 1 FROM traffic_event_hits LIMIT 1)", "trusted_sources_present": "SELECT EXISTS(SELECT 1 FROM traffic_aggregation_records WHERE kind='evidence_sources' AND record_key='active')"} {
		var present bool
		if db.QueryRowContext(ctx, query).Scan(&present) != nil {
			fail("validation inventory query failed")
		}
		inventory[name] = present
	}
	acceptance := "sample_evaluated"
	evaluated := 0
	for _, r := range results {
		if r.Evaluation.Status == "evaluated" {
			evaluated++
		}
	}
	if evaluated == 0 {
		acceptance = "blocked_no_evaluable_snapshots"
		onlyLegacy := true
		for _, r := range results {
			onlyLegacy = onlyLegacy && r.Evaluation.Reason == "legacy_snapshot_unverified"
		}
		if onlyLegacy {
			acceptance = "blocked_no_snapshot_events"
		}
	} else if evaluated < len(results) {
		acceptance = "partial_sample_evaluated"
	}
	report := map[string]any{"at": time.Now().UTC(), "database": settings.DBName, "read_only": true, "llm_calls": 0, "sampling": "bounded snapshot record-key sample; latest snapshot per unique event; fallback to recent legacy events when empty", "sample_record_limit": *sample, "validated_events": len(results), "evaluated_snapshot_events": evaluated, "acceptance_status": acceptance, "inventory": inventory, "results": results}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fail("validation export failed")
	}
	if *output != "" {
		if os.WriteFile(*output, raw, 0600) != nil {
			fail("validation output write failed")
		}
		fmt.Printf("validated_events=%d output=%s\n", len(results), *output)
	} else {
		fmt.Println(string(raw))
	}
}

func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
