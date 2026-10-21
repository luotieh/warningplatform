// remaining-evidence-audit exports the runtime registry and replays detached
// collections. It has no database configuration or live model integration.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/mockscenario"
	"vulnscan-backend/traffic/internal/service"
)

func save(dir, name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func run() error {
	collection := flag.String("collection", "", "saved platform collection; no network access")
	bundle := flag.String("bundle", "", "saved prepared input, mutually exclusive with collection")
	out := flag.String("output", "", "new output directory")
	stub := flag.Bool("stub", false, "controlled semantic stub only")
	flag.Parse()
	if *out == "" || *collection != "" && *bundle != "" {
		return fmt.Errorf("specify new output and at most one input")
	}
	if _, err := os.Stat(*out); !os.IsNotExist(err) {
		return fmt.Errorf("output must not exist")
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		return err
	}
	if err := save(*out, "catalog.json", map[string]any{"facts": evidence.Definitions(), "semantics": evidence.SemanticDefinitions(), "semantic_dependencies": evidence.SemanticDependencyDefinitions()}); err != nil {
		return err
	}
	if *collection == "" && *bundle == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var b service.PreparedEvidenceBundle
	started := time.Now()
	if *collection != "" {
		raw, err := os.ReadFile(*collection)
		if err != nil {
			return err
		}
		var c service.EvidenceCollection
		if err = json.Unmarshal(raw, &c); err != nil {
			return err
		}
		before, _ := json.Marshal(c)
		var audit service.EvidenceSupplyAudit
		b, audit, err = service.PreprocessCollectedEvidence(ctx, c)
		if err != nil {
			return err
		}
		after, _ := json.Marshal(c)
		if string(before) != string(after) {
			return fmt.Errorf("collection mutated")
		}
		if err = save(*out, "audit.json", service.ProviderRedactedAudit(audit)); err != nil {
			return err
		}
	} else {
		f, err := os.Open(*bundle)
		if err != nil {
			return err
		}
		b, err = service.DecodePreparedEvidence(f)
		f.Close()
		if err != nil {
			return err
		}
	}
	preprocessNS := time.Since(started).Nanoseconds()
	opts := service.PreparedExecutionOptions{SemanticMode: service.PreparedSemanticDisabled}
	if *stub {
		opts.SemanticMode = service.PreparedSemanticStub
		opts.SemanticModel = &mockscenario.ControlledModel{}
	}
	started = time.Now()
	r, err := service.ExecutePreparedEvidence(ctx, b, opts)
	if err != nil {
		return err
	}
	if err = save(*out, "prepared-bundle.json", b); err != nil {
		return err
	}
	if err = save(*out, "normalized-result.json", r); err != nil {
		return err
	}
	return save(*out, "replay.json", map[string]any{"event_id": b.Event.EventID, "collection_unchanged": true, "collection_reprocessed": *collection != "", "preprocess_or_decode_ns": preprocessNS, "execute_and_serialize_ns": time.Since(started).Nanoseconds(), "database_calls": 0, "real_model_calls": 0, "semantic_stub": *stub})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
