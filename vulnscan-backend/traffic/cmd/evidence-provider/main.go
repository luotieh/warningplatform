// evidence-provider is an explicitly invoked, read-only alternative input path.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"vulnscan-backend/traffic/internal/mockscenario"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func write(dir, name string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0600)
}
func run() error {
	event := flag.String("event", "", "existing EventID")
	out := flag.String("output", "./evidence-provider-result", "new local result directory")
	fixture := flag.String("fixture", "", "isolated platform-row fixture (never a PreparedBundle)")
	dsnEnv := flag.String("dsn-env", "", "environment variable holding authorized TEST MySQL DSN; no initialization/migration")
	contracts := flag.String("contracts", "../docs/evidence-pipeline-v2.1/input-field-map.json", "existing v2.1 field contract index")
	profile := flag.String("profile", "traffic/internal/service/testdata/prepared-controlled-http.json", "existing bundle: read execution configuration ONLY")
	baseline := flag.Bool("compare-snapshot", false, "also execute original snapshot preparation against the same isolated fixture; never against SQL")
	start := flag.String("start", "", "RFC3339 inclusive activity window")
	end := flag.String("end", "", "RFC3339 exclusive activity window")
	lookback := flag.Int("lookback-days", 30, "history days (1..90)")
	maxHits := flag.Int("max-hits", 5000, "total bounded hit budget")
	maxEvents := flag.Int("max-events", 200, "candidate event budget")
	execute := flag.Bool("execute", false, "execute existing F/S/C and normalization")
	collectOnly := flag.Bool("collect-only", false, "save platform collection without preprocessing or execution")
	semantic := flag.String("semantic", "disabled", "disabled or controlled stub; no live API")
	flag.Parse()
	if *lookback < 1 || *lookback > 90 || *maxHits < 1 || *maxEvents < 1 {
		return fmt.Errorf("query_window_or_budget_invalid")
	}
	if *event == "" || (*fixture == "") == (*dsnEnv == "") {
		return fmt.Errorf("specify event and exactly one of fixture or dsn-env")
	}
	if *semantic != "disabled" && *semantic != "stub" {
		return fmt.Errorf("only_disabled_or_stub_allowed")
	}
	if *collectOnly && (*execute || *baseline) {
		return fmt.Errorf("collect_only_cannot_execute_or_compare")
	}
	if _, e := os.Stat(*out); e == nil {
		return fmt.Errorf("output_exists_choose_new_directory")
	}
	if e := os.MkdirAll(*out, 0700); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var reader store.EvidenceReader
	var fixtureStore *store.MemoryStore
	if *fixture != "" {
		r, e := loadFixture(ctx, *fixture)
		if e != nil {
			return e
		}
		reader = r
		fixtureStore = r
	} else {
		dsn := os.Getenv(*dsnEnv)
		if dsn == "" {
			return fmt.Errorf("test_database_dsn_not_configured")
		}
		db, e := sql.Open("mysql", dsn)
		if e != nil {
			return fmt.Errorf("test_database_open_failed")
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		if e = db.PingContext(ctx); e != nil {
			return fmt.Errorf("test_database_connect_failed")
		}
		r, closeRead, e := store.NewEvidenceReadTransaction(ctx, db)
		if e != nil {
			return fmt.Errorf("readonly_repeatable_read_transaction_failed")
		}
		defer closeRead()
		reader = r
	}
	raw, e := os.ReadFile(*contracts)
	if e != nil {
		return e
	}
	var fields []service.EvidenceFieldContract
	if e = json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	o := service.EvidenceQueryOptions{Contracts: fields, Lookback: time.Duration(*lookback) * 24 * time.Hour, MaxHits: *maxHits, MaxEvents: *maxEvents}
	if *baseline && fixtureStore == nil {
		return fmt.Errorf("snapshot_comparison_requires_isolated_fixture")
	}
	profileRaw, e := os.ReadFile(*profile)
	if e != nil {
		return e
	}
	var profileConfig service.EvidenceExecutionProfile
	if e = json.Unmarshal(profileRaw, &profileConfig); e != nil {
		return e
	}
	o.Profile = &profileConfig
	if *start != "" {
		o.Start, e = time.Parse(time.RFC3339Nano, *start)
		if e != nil {
			return e
		}
	}
	if *end != "" {
		o.End, e = time.Parse(time.RFC3339Nano, *end)
		if e != nil {
			return e
		}
	}
	collected, e := service.CollectEvidenceFromPlatform(ctx, reader, *event, o)
	a := collected.Audit
	if e == nil {
		if e = write(*out, "platform-collection.json", collected); e != nil {
			return e
		}
	}
	var b service.PreparedEvidenceBundle
	if e == nil && !*collectOnly {
		b, a, e = service.PreprocessCollectedEvidence(ctx, collected)
	}
	if err := write(*out, "query-plan.json", a.Queries); err != nil {
		return err
	}
	if err := write(*out, "evidence-supply-audit.json", service.ProviderRedactedAudit(a)); err != nil {
		return err
	}
	if e != nil {
		return e
	}
	if *collectOnly {
		fmt.Printf("event=%s collection_valid=true preprocessing=false writes=0\n", *event)
		return nil
	}
	if e = write(*out, "prepared-bundle.json", b); e != nil {
		return e
	}
	if e = write(*out, "query-trace.json", a.Trace); e != nil {
		return e
	}
	if e = write(*out, "coverage-proof-matrix.json", a.CoverageProofs); e != nil {
		return e
	}
	if !*execute {
		return nil
	}
	opts := service.PreparedExecutionOptions{SemanticMode: service.PreparedSemanticDisabled}
	if *semantic == "stub" {
		opts.SemanticMode = service.PreparedSemanticStub
		opts.SemanticModel = &mockscenario.ControlledModel{}
	}
	result, e := service.ExecutePreparedEvidence(ctx, b, opts)
	if e != nil {
		return e
	}
	if e = write(*out, "query-trace.json", append(a.Trace, service.ProviderExecutionTrace(b, result)...)); e != nil {
		return e
	}
	var semanticPlan any
	if result.Semantics.Result != nil {
		semanticPlan = result.Semantics.Result.Plan
	}
	outputs := map[string]any{"f-results.json": result.Evaluation, "semantic-plan.json": semanticPlan, "semantic-results.json": result.Semantics, "joint-evidence.json": result.Evidence.PhaseOne, "normalized-result.json": result, "rule-readiness.json": result.Evidence.Pipeline.Checks, "execution-mode.json": map[string]any{"semantic_mode": *semantic, "real_model_calls": 0, "business_database_writes": 0, "fixture": *fixture != ""}}
	for name, value := range outputs {
		if e = write(*out, name, value); e != nil {
			return e
		}
	}
	if *baseline {
		p := service.EvidencePipeline{Services: service.Services{Store: fixtureStore, ReportSemantics: &b.SemanticOptions, PhaseOnePolicy: &b.JointConfig, SemanticModel: opts.SemanticModel}}
		old, e := p.PrepareEvidenceBundle(ctx, *event)
		if e != nil {
			return fmt.Errorf("snapshot_baseline_prepare:%w", e)
		}
		// Baseline follows the original in-process formal entry, including its
		// own untouched input preparation and configuration.
		legacy, e := p.Execute(ctx, *event, service.EvidencePipelineOptions{Persist: false})
		if e != nil {
			return e
		}
		if e = write(*out, "snapshot-baseline-bundle.json", old); e != nil {
			return e
		}
		if e = write(*out, "snapshot-baseline-result.json", legacy); e != nil {
			return e
		}
	}
	fmt.Printf("event=%s bundle_valid=%t queries=%d fields=%d catalog=%d semantic=%s real_model_calls=0 writes=0\n", *event, a.Valid, len(a.Queries), len(a.Fields), len(result.Evidence.Pipeline.Checks), *semantic)
	return nil
}
