package monitoragent

import (
	"context"
	"encoding/json"
	"strings"
)

type SensitiveWordEngine struct {
	Rules RuleStore
}

func (e *SensitiveWordEngine) Name() string { return "sensitive_word" }

func (e *SensitiveWordEngine) Run(ctx context.Context, task *TaskMessage, snap *PageSnapshot) (map[string]any, error) {
	result := map[string]any{
		"url":     task.URL,
		"has_hit": false,
	}

	if snap == nil || snap.Error != "" {
		return result, nil
	}

	words := e.loadSensitiveWords()
	text := strings.ToLower(snap.VisibleText)
	title := strings.ToLower(snap.Title)

	var matches []map[string]any
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

	result["matches"] = matches
	result["total_matches"] = totalMatches
	result["text_length"] = len(snap.VisibleText)

	if len(matches) > 0 {
		result["has_hit"] = true
	}

	return result, nil
}

type sensitiveWord struct {
	Word     string `json:"word"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

func (e *SensitiveWordEngine) loadSensitiveWords() []sensitiveWord {
	if e.Rules == nil {
		return nil
	}

	allRules, err := e.Rules.GetAllRules()
	if err != nil {
		return nil
	}

	var words []sensitiveWord
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
