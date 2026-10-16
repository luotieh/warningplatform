// evidence-replay executes a versioned L2 bundle without any database or
// configured LLM. Mock semantics are opt-in and always labeled as controlled.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/service"
)

type neutralModel struct{}

func (neutralModel) Complete(_ context.Context, call evidence.SemanticCall) (string, error) {
	var request struct {
		Tasks []evidence.SemanticTask `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(call.Prompt), &request); err != nil {
		return "", err
	}
	items := []evidence.SemanticItem{}
	for _, task := range request.Tasks {
		item := evidence.SemanticItem{TaskID: task.ID, Judgement: "neutral", Strength: "none", Explanation: "受控Mock中立响应，仅验证接口与结构，不是模型语义结论", Alternatives: []string{"需要真实模型与人工语义验收"}, Gaps: []string{"没有执行真实模型"}, MaterialRefs: []string{}, FactRefs: []string{}, AdjudicationRefs: []string{}, Quotes: []evidence.SemanticQuote{}}
		for _, m := range task.Materials {
			item.MaterialRefs = append(item.MaterialRefs, m.ID)
			runes := []rune(m.Text)
			item.Quotes = append(item.Quotes, evidence.SemanticQuote{MaterialID: m.ID, Excerpt: string(runes[:min(24, len(runes))])})
			if m.AdjudicationID != "" {
				item.AdjudicationRefs = append(item.AdjudicationRefs, m.AdjudicationID)
			}
		}
		for _, f := range task.Facts {
			item.FactRefs = append(item.FactRefs, f.ID)
		}
		items = append(items, item)
	}
	raw, err := json.Marshal(map[string]any{"items": items})
	return string(raw), err
}

func main() {
	input := flag.String("input", "", "prepared bundle JSON")
	output := flag.String("output", "", "output JSON path (required)")
	mock := flag.Bool("mock-semantics", false, "use controlled neutral mock; never a real model")
	flag.Parse()
	if err := run(*input, *output, *mock); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(input, output string, mock bool) error {
	if input == "" || output == "" || input == output {
		return fmt.Errorf("distinct -input and -output paths are required")
	}
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	b, err := service.DecodePreparedEvidence(f)
	f.Close()
	if err != nil {
		return err
	}
	opts := service.PreparedExecutionOptions{}
	if mock {
		opts.SemanticModel = neutralModel{}
		b.SemanticOptions.ModelVersion = "controlled-mock-neutral-not-real-model"
		b.Seal()
	}
	out, err := service.ExecutePreparedEvidence(context.Background(), b, opts)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(map[string]any{"mock_semantics": mock, "real_model_executed": false, "input_digest": b.InputDigest, "result": out}, "", "  ")
	if err != nil {
		return err
	}
	// Refuse to overwrite existing inputs or previous acceptance artifacts.
	w, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	closeErr := w.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	a := out.Evidence.Pipeline
	fmt.Printf("59F/23S: completed=%d/%d; mock_semantics=%t; database=false; output=%s\n", a.Completed, a.Total, mock, output)
	return nil
}
