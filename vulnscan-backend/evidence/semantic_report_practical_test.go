package evidence

import (
	"context"
	"testing"
)

func TestReportPracticalSemanticOptionalInputsRemainOptionalOnlyForReports(t *testing.T) {
	for _, id := range []string{"S03", "S05", "S06", "S14", "SC03"} {
		var spec slotSpec
		for _, s := range semanticSpecs {
			if s.Key.ID == id {
				spec = s
				break
			}
		}
		r := semanticFixture(spec)
		materials := []SemanticMaterial{}
		for _, m := range r.Subjects[0].Materials {
			if m.Kind != "asset_role" && m.Kind != "task_context" && m.Kind != "brand_authorization" && m.Kind != "brand_relation" {
				materials = append(materials, m)
			}
		}
		r.Subjects[0].Materials = materials
		if id == "S03" || id == "S06" {
			r.Subjects[0].Facts = nil
		}
		if id == "S06" {
			for n := range r.Subjects[0].Materials {
				r.Subjects[0].Materials[n].Provenance.Complete = false
				r.Subjects[0].Materials[n].Truncated = true
			}
		}
		cfg := DefaultSemanticConfig()
		cfg.ReportPractical = true
		e, err := NewSemanticEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		p, err := e.Plan(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Tasks) != 1 {
			t.Fatalf("%s still gated: %+v", id, p)
		}
		if id != "S14" && p.Tasks[0].MaxStrength != "weak" {
			t.Fatalf("%s incorrectly upgraded", id)
		}
		cfg.ReportPractical = false
		e, _ = NewSemanticEngine(cfg)
		p, err = e.Plan(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Tasks) != 0 {
			t.Fatalf("%s changed non-report behavior", id)
		}
	}
}
