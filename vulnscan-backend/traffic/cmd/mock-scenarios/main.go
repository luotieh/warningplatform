// mock-scenarios runs the standard PreparedEvidenceBundle executor offline.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"vulnscan-backend/traffic/internal/mockscenario"
)

func main() {
	root := flag.String("root", "../docs/evidence-pipeline-v2/mock-scenarios", "artifact directory")
	scenario := flag.String("scenario", "all", "all, c2, botnet, phishing, network-activity")
	generate := flag.Bool("generate", false, "create new standard input fixtures; refuses overwrite")
	template := flag.String("template", "traffic/internal/service/testdata/prepared-controlled-http.json", "official L2 example for contract configuration")
	flag.Parse()
	if err := run(*root, *scenario, *generate, *template); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(root, selected string, generate bool, template string) error {
	if generate {
		return mockscenario.Generate(root, template)
	}
	names := []struct{ id, dir string }{{"c2", "mock-01-c2-beacon"}, {"botnet", "mock-02-botnet-coordination"}, {"phishing", "mock-03-phishing-credential"}, {"network-activity", "mock-04-network-exploit"}}
	found := false
	for _, n := range names {
		if selected != "all" && selected != n.id {
			continue
		}
		found = true
		o, e := mockscenario.Run(context.Background(), filepath.Join(root, n.dir))
		if e != nil {
			return fmt.Errorf("%s: %w", n.id, e)
		}
		instances := 0
		for _, item := range o.Evidence.Normalized.Items {
			if item.Kind == "fact" || item.Kind == "semantic" {
				instances++
			}
		}
		fmt.Printf("%s: catalog=%d/82 F/S instances=%d controlled S accepted=%d C score=%d repeat=equal database=false\n", n.id, o.Evidence.Pipeline.Completed, instances, len(o.Semantics.Result.Findings), o.Evidence.PhaseOne.Result.Score)
	}
	if !found {
		return fmt.Errorf("unknown scenario %q", selected)
	}
	return nil
}
