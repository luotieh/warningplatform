package analyzer

import (
	"html"
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

const maxTamperEvidenceRunes = 120_000

// TamperCompareEvidence 双栏对比证据（左：基线/删除，右：当前/新增）。
type TamperCompareEvidence struct {
	BaselineHTML string `json:"baseline_html"`
	CurrentHTML  string `json:"current_html"`
	HasBaseline  bool   `json:"has_baseline"`
	Truncated    bool   `json:"truncated,omitempty"`
}

func tamperCompareText(snap *snapshotData) string {
	return combineSearchText(snap)
}

func buildTamperCompareEvidence(baselineText, currentText string) TamperCompareEvidence {
	baselineText = strings.TrimSpace(baselineText)
	currentText = strings.TrimSpace(currentText)
	out := TamperCompareEvidence{HasBaseline: baselineText != ""}

	if baselineText == "" && currentText == "" {
		return out
	}
	if baselineText == "" {
		out.CurrentHTML = html.EscapeString(truncateRunes(currentText, maxTamperEvidenceRunes))
		out.Truncated = len([]rune(currentText)) > maxTamperEvidenceRunes
		return out
	}
	if currentText == "" {
		out.BaselineHTML = html.EscapeString(truncateRunes(baselineText, maxTamperEvidenceRunes))
		out.Truncated = len([]rune(baselineText)) > maxTamperEvidenceRunes
		return out
	}

	baseRunes := []rune(baselineText)
	curRunes := []rune(currentText)
	if len(baseRunes) > maxTamperEvidenceRunes {
		baselineText = string(baseRunes[:maxTamperEvidenceRunes])
		out.Truncated = true
	}
	if len(curRunes) > maxTamperEvidenceRunes {
		currentText = string(curRunes[:maxTamperEvidenceRunes])
		out.Truncated = true
	}

	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(baselineText, currentText, false)
	diffs = dmp.DiffCleanupSemantic(diffs)

	var left, right strings.Builder
	for _, d := range diffs {
		switch d.Type {
		case diffmatchpatch.DiffEqual:
			esc := html.EscapeString(d.Text)
			left.WriteString(esc)
			right.WriteString(esc)
		case diffmatchpatch.DiffDelete:
			left.WriteString(`<del class="tp-del">`)
			left.WriteString(html.EscapeString(d.Text))
			left.WriteString(`</del>`)
		case diffmatchpatch.DiffInsert:
			right.WriteString(`<ins class="tp-ins">`)
			right.WriteString(html.EscapeString(d.Text))
			right.WriteString(`</ins>`)
		}
	}
	out.BaselineHTML = left.String()
	out.CurrentHTML = right.String()
	return out
}

func buildTamperFirstRunEvidence(currentText string) TamperCompareEvidence {
	currentText = strings.TrimSpace(currentText)
	if currentText == "" {
		return TamperCompareEvidence{}
	}
	truncated := len([]rune(currentText)) > maxTamperEvidenceRunes
	text := truncateRunes(currentText, maxTamperEvidenceRunes)
	esc := html.EscapeString(text)
	return TamperCompareEvidence{
		BaselineHTML: esc,
		CurrentHTML:  esc,
		HasBaseline:  true,
		Truncated:    truncated,
	}
}
