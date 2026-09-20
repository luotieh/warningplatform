// Local maintenance tool. Database credentials are read from the environment,
// never embedded in a manifest or printed in command output.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"vulnscan-backend/traffic/internal/service"
	"vulnscan-backend/traffic/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	mode := flag.String("mode", "audit", "audit, apply, rollback, or migrate")
	file := flag.String("manifest", "", "audit output/apply input file (contains original evidence; protect it)")
	batch := flag.String("batch", "", "rollback batch ID")
	event := flag.String("event", "", "audit only this event's complete directional aggregation group")
	flag.Parse()
	dsn := os.Getenv("TRAFFIC_REPAIR_DSN")
	if dsn == "" {
		return fmt.Errorf("TRAFFIC_REPAIR_DSN is required")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return fmt.Errorf("invalid database configuration")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.MultiStatements = *mode == "migrate"
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return fmt.Errorf("cannot open database")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		return fmt.Errorf("database connection failed")
	}
	svc := service.Services{Store: store.NewMySQLStore(db)}
	switch *mode {
	case "audit", "dry-run":
		if *file == "" {
			return fmt.Errorf("--manifest is required")
		}
		plan, err := svc.AuditAggregationGroup(ctx, *event)
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = f.Write(raw); err != nil {
			return err
		}
		fmt.Printf("Read-only audit: %d events, batch %s, checksum %s\n", len(plan.Entries), plan.BatchID, plan.Checksum)
		return nil
	case "apply":
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var plan service.RepairPlan
		if err = json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		if err = svc.ApplyAggregationRepair(ctx, plan); err != nil {
			return err
		}
		fmt.Println("Applied batch", plan.BatchID, "(no model calls)")
		return nil
	case "rollback":
		if *batch == "" {
			return fmt.Errorf("--batch is required")
		}
		if err = svc.RollbackAggregationRepair(ctx, *batch); err != nil {
			return err
		}
		fmt.Println("Rolled back batch", *batch, "; immutable source records retained")
		return nil
	case "migrate":
		_, err = db.ExecContext(ctx, store.AggregationSchema)
		if err != nil {
			return err
		}
		fmt.Println("Aggregation migration 20260918 applied; existing event data unchanged")
		return nil
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}
