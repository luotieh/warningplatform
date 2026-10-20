package mockscenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/service"
)

type StubCall struct {
	Tasks    []evidence.SemanticTask `json:"tasks"`
	Response json.RawMessage         `json:"response"`
}
type ControlledModel struct{ Calls []StubCall }

// Decisions inspect delivered material, never expected F/C results. This is
// deliberately a controlled protocol fixture, not a semantic classifier.
func (m *ControlledModel) Complete(_ context.Context, c evidence.SemanticCall) (string, error) {
	var req struct {
		Tasks []evidence.SemanticTask `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(c.Prompt), &req); err != nil {
		return "", err
	}
	items := []evidence.SemanticItem{}
	for _, t := range req.Tasks {
		all := ""
		for _, a := range t.Materials {
			all += "\n" + a.Text
		}
		item := evidence.SemanticItem{TaskID: t.ID, Judgement: "neutral", Strength: "none", Explanation: "受控Stub：材料不足以建立该语义；只验证引用合同。", MaterialRefs: []string{}, FactRefs: []string{}, AdjudicationRefs: []string{}, Quotes: []evidence.SemanticQuote{}, Alternatives: []string{"需要真实模型及人工标注验收"}, Gaps: []string{"未证明任何主机执行或攻击成功"}}
		support := false
		switch t.Slot.Key.ID {
		case "S01", "S02":
			support = strings.Contains(all, "MOCK_COMMAND_REQUEST")
		case "S13":
			support = t.Slot.Key.Subtype == "command" && strings.Contains(all, "MOCK_COMMAND_REQUEST")
		case "S09":
			support = strings.Contains(all, "MOCK_EXPLOIT_TEST")
		case "S05", "S06", "S12", "SC03":
			support = strings.Contains(all, "cont0so.test") || strings.Contains(all, "collector-fixture.test")
		case "BT-S01":
			support = len(t.Facts) > 0
		}
		if support && !t.Slot.ExplanationOnly {
			item.Judgement = "support"
			item.Strength = t.MaxStrength
			item.Explanation = "受控Stub：实际交付的合成测试内容符合本场景的解释设定，不代表真实模型或攻击结果。"
		}
		if strings.Contains(all, "accounts.contoso.test") && !strings.Contains(all, "collector-fixture.test") && (t.Slot.Key.ID == "S01" || t.Slot.Key.ID == "S06") || strings.Contains(all, "GET /health") && (t.Slot.Key.ID == "S01" || t.Slot.Key.ID == "S09") {
			item.Judgement = "contradict"
			item.Strength = "weak"
			if t.MaxStrength == "none" {
				item.Strength = "none"
			}
			item.Explanation = "受控Stub：本事务是合成授权正常业务对照，不支持该恶意意图。"
		}
		for _, a := range t.Materials {
			item.MaterialRefs = append(item.MaterialRefs, a.ID)
			r := []rune(a.Text)
			item.Quotes = append(item.Quotes, evidence.SemanticQuote{MaterialID: a.ID, Excerpt: string(r[:min(80, len(r))])})
			if a.AdjudicationID != "" {
				item.AdjudicationRefs = append(item.AdjudicationRefs, a.AdjudicationID)
			}
		}
		for _, f := range t.Facts {
			item.FactRefs = append(item.FactRefs, f.ID)
		}
		items = append(items, item)
	}
	raw, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		return "", err
	}
	m.Calls = append(m.Calls, StubCall{Tasks: req.Tasks, Response: raw})
	return string(raw), nil
}

func WriteJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0600)
}
func readBundle(path string) (service.PreparedEvidenceBundle, error) {
	f, e := os.Open(path)
	if e != nil {
		return service.PreparedEvidenceBundle{}, e
	}
	defer f.Close()
	return service.DecodePreparedEvidence(f)
}
func writeBundle(path string, b service.PreparedEvidenceBundle) error {
	var buf bytes.Buffer
	if e := service.EncodePreparedEvidence(&buf, b); e != nil {
		return e
	}
	var v any
	if e := json.Unmarshal(buf.Bytes(), &v); e != nil {
		return e
	}
	return WriteJSON(path, v)
}

func Generate(root, templatePath string) error {
	t, err := readBundle(templatePath)
	if err != nil {
		return err
	}
	scenarios, err := Build(t)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(root, 0755); err != nil {
		return err
	}
	for _, s := range scenarios {
		dir := filepath.Join(root, s.Directory)
		if err = os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if _, e := os.Stat(filepath.Join(dir, "prepared-bundle.json")); e == nil {
			return fmt.Errorf("fixture exists; generation refuses overwrite: %s", dir)
		}
		if err = writeBundle(filepath.Join(dir, "prepared-bundle.json"), s.Bundle); err != nil {
			return err
		}
		if err = WriteJSON(filepath.Join(dir, "scenario.json"), s); err != nil {
			return err
		}
		if err = WriteJSON(filepath.Join(dir, "sources.json"), s.Sources); err != nil {
			return err
		}
	}
	if err = WriteJSON(filepath.Join(root, "prepared-evidence.schema.json"), service.PreparedEvidenceJSONSchema()); err != nil {
		return err
	}
	if err = WriteJSON(filepath.Join(root, "normalized-evidence.schema.json"), service.NormalizedExecutionJSONSchema()); err != nil {
		return err
	}
	inputs := map[string]any{}
	for _, id := range evidence.SupportedFacts() {
		inputs[string(id)] = evidence.FactInputs(id)
	}
	return WriteJSON(filepath.Join(root, "catalog-contracts.json"), map[string]any{"facts": evidence.Definitions(), "fact_inputs": inputs, "semantics": evidence.SemanticDependencyDefinitions()})
}

func Run(ctx context.Context, dir string) (service.PreparedEvidenceExecution, error) {
	var out service.PreparedEvidenceExecution
	start := time.Now()
	b, err := readBundle(filepath.Join(dir, "prepared-bundle.json"))
	if err != nil {
		return out, err
	}
	if err = WriteJSON(filepath.Join(dir, "input-validation.json"), map[string]any{"passed": true, "go_wire_and_binding_validation": true, "input_digest": b.InputDigest, "schema_version": b.SchemaVersion, "synthetic_fixture": true, "schema_external_validation": "schema-validation.json", "elapsed_ms": time.Since(start).Milliseconds()}); err != nil {
		return out, err
	}
	m := &ControlledModel{}
	executeStart := time.Now()
	out, err = service.ExecutePreparedEvidence(ctx, b, service.PreparedExecutionOptions{SemanticMode: service.PreparedSemanticStub, SemanticModel: m})
	if err != nil {
		return out, err
	}
	if out.Semantics.Result == nil {
		WriteJSON(filepath.Join(dir, "failed-execution.json"), out)
		return out, fmt.Errorf("semantic result missing: %+v", out.Semantics)
	}
	if err = service.ValidatePreparedExecution(b, out); err != nil {
		return out, err
	}
	if err = verifySources(dir, b, out); err != nil {
		return out, err
	}
	if out.Evidence.Pipeline.Completed != 82 || len(out.Evidence.Pipeline.Checks) != 82 {
		return out, fmt.Errorf("catalog incomplete")
	}
	for _, c := range out.Evidence.Pipeline.Checks {
		if c.States["execution_error"] > 0 {
			return out, fmt.Errorf("execution error %s: %+v", c.ID, c.Reasons)
		}
	}
	sem := out.Semantics.Result
	if len(sem.Plan.Tasks) != len(sem.Findings) {
		return out, fmt.Errorf("planned semantic tasks were not all accepted: tasks=%d findings=%d", len(sem.Plan.Tasks), len(sem.Findings))
	}
	if err = evidence.ValidateSemanticResult(sem.Plan, *sem); err != nil {
		return out, err
	}
	// Execute again from exactly the same immutable input; compare semantic
	// values while excluding only the executor's explicitly elapsed metrics.
	m2 := &ControlledModel{}
	repeat, err := service.ExecutePreparedEvidence(ctx, b, service.PreparedExecutionOptions{SemanticMode: service.PreparedSemanticStub, SemanticModel: m2})
	if err != nil {
		return out, err
	}
	stable := stableDigest(out)
	if stable != stableDigest(repeat) {
		return out, fmt.Errorf("non-deterministic semantic results")
	}
	factChecks := []service.PipelineCheck{}
	semanticChecks := []service.PipelineCheck{}
	for _, c := range out.Evidence.Pipeline.Checks {
		if c.Kind == "fact" {
			factChecks = append(factChecks, c)
		} else {
			semanticChecks = append(semanticChecks, c)
		}
	}
	files := map[string]any{
		"normalized-result.json":   out,
		"f-results.json":           map[string]any{"catalog": factChecks, "result": out.Evaluation.Result, "manifest": out.Evaluation.Manifest},
		"semantic-plan.json":       sem.Plan,
		"semantic-results.json":    map[string]any{"catalog": semanticChecks, "result": sem, "controlled_stub": true, "real_model_executed": false},
		"semantic-validation.json": map[string]any{"passed": true, "validator": "evidence.ValidateSemanticResult", "accepted": len(sem.Findings), "calls": m.Calls, "real_model_executed": false, "claim": "Only controlled task execution, quotes, references, transaction/decode/strength contracts; no semantic accuracy claim"},
		"joint-evidence.json":      out.Evidence.PhaseOne.Result,
		"execution-metadata.json":  map[string]any{"tool_version": Version, "database": false, "external_http": false, "real_model_executed": false, "persisted": out.Evidence.Pipeline.Persisted, "input_digest": b.InputDigest, "semantic_result_sha256": stable, "repeat_equal": true, "decode_ms": executeStart.Sub(start).Milliseconds(), "execute_and_verify_ms": time.Since(executeStart).Milliseconds(), "stages": out.Evidence.Pipeline.Metrics, "source_validation": true, "normalized_validation": true},
	}
	for name, v := range files {
		if err = WriteJSON(filepath.Join(dir, name), v); err != nil {
			return out, err
		}
	}
	return out, nil
}

func stableDigest(o service.PreparedEvidenceExecution) string {
	raw, _ := json.Marshal([]any{o.Evaluation.Result, o.Semantics.Result.Plan, o.Semantics.Result.Findings, o.Evidence.PhaseOne.Result, o.Evidence.Normalized, o.Contract})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func verifySources(dir string, b service.PreparedEvidenceBundle, o service.PreparedEvidenceExecution) error {
	raw, e := os.ReadFile(filepath.Join(dir, "sources.json"))
	if e != nil {
		return e
	}
	sources := map[string]json.RawMessage{}
	if e = json.Unmarshal(raw, &sources); e != nil {
		return e
	}
	for _, h := range b.Inputs.Request.Hits {
		if _, ok := sources[h.ID]; !ok {
			return fmt.Errorf("unregistered hit: %s", h.ID)
		}
	}
	for _, n := range o.Evidence.Normalized.Items {
		for _, id := range n.SourceIDs {
			if _, ok := sources[id]; !ok {
				return fmt.Errorf("unregistered normalized source: %s rule=%s", id, n.RuleID)
			}
		}
	}
	return nil
}
