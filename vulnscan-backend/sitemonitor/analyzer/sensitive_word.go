package analyzer

import (
	"context"
	"encoding/json"
	"strings"
)

type SensitiveWordAnalyzer struct {
	rules RuleAccessor
}

func NewSensitiveWordAnalyzer(rules RuleAccessor) *SensitiveWordAnalyzer {
	return &SensitiveWordAnalyzer{rules: rules}
}

func (a *SensitiveWordAnalyzer) Dimension() string { return "sensitive_word" }

func (a *SensitiveWordAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	snap, err := parseSnapshot(input.SnapshotJSON)
	if err != nil {
		return nil, err
	}

	output := &Output{HasIssue: false}
	if snap.Error != "" {
		return output, nil
	}

	words := a.loadSensitiveWords()
	text := strings.ToLower(snap.VisibleText)
	title := strings.ToLower(snap.Title)

	matches := make([]map[string]any, 0)
	totalMatches := 0

	for _, word := range words {
		lw := strings.ToLower(word.Word)
		count := strings.Count(text, lw)
		titleCount := strings.Count(title, lw)
		total := count + titleCount

		if total > 0 {
			matchInfo := map[string]any{
				"word":     word.Word,
				"category": word.Category,
				"severity": word.Severity,
				"count":    total,
			}

			if idx := strings.Index(text, lw); idx >= 0 {
				start := idx - 50
				if start < 0 {
					start = 0
				}
				end := idx + len(lw) + 50
				if end > len(text) {
					end = len(text)
				}
				matchInfo["context"] = text[start:end]
			}

			matches = append(matches, matchInfo)
			totalMatches += total
		}
	}

	if len(matches) > 0 {
		output.HasIssue = true
		if totalMatches > 10 {
			output.Severity = "high"
		} else if totalMatches > 3 {
			output.Severity = "medium"
		} else {
			output.Severity = "low"
		}
		detailJSON, _ := json.Marshal(map[string]any{
			"matches":       matches,
			"total_matches": totalMatches,
			"text_length":   len(snap.VisibleText),
		})
		output.DetailsJSON = string(detailJSON)
	}

	return output, nil
}

type sensitiveWord struct {
	Word     string `json:"word"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

func (a *SensitiveWordAnalyzer) loadSensitiveWords() []sensitiveWord {
	if a.rules == nil {
		return nil
	}

	allRules, err := a.rules.GetAllRules()
	if err != nil {
		return nil
	}

	words := make([]sensitiveWord, 0)
	for key, data := range allRules {
		if !strings.HasPrefix(key, "lib/word/") {
			continue
		}
		var lib struct {
			Categories []struct {
				Name    string `json:"name"`
				Entries []struct {
					Word     string `json:"word"`
					Severity string `json:"severity"`
				} `json:"entries"`
			} `json:"categories"`
		}
		if err := json.Unmarshal(data, &lib); err != nil {
			continue
		}
		for _, cat := range lib.Categories {
			for _, entry := range cat.Entries {
				sev := entry.Severity
				if sev == "" {
					sev = "medium"
				}
				words = append(words, sensitiveWord{
					Word:     entry.Word,
					Category: cat.Name,
					Severity: sev,
				})
			}
		}
	}

	return words
}
