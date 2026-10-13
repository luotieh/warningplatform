package config

import (
	"fmt"
	"github.com/pelletier/go-toml/v2"
	"os"
	"strconv"
)

// ReportOptions affect formal reports only. Zero budgets preserve old defaults.
type ReportOptions struct {
	InputTokens   int    `toml:"report_input_token_limit" json:"input_token_limit"`
	OutputTokens  int    `toml:"report_output_token_limit" json:"output_token_limit"`
	ContextTokens int    `toml:"report_context_window_tokens" json:"context_window_tokens"`
	SafetyTokens  int    `toml:"report_token_safety_margin" json:"safety_margin_tokens"`
	LogEnabled    *bool  `toml:"report_log_enabled" json:"log_enabled"`
	LogDir        string `toml:"report_log_dir" json:"log_dir"`
	RetentionDays int    `toml:"report_log_retention_days" json:"log_retention_days"`
}

func LoadReportOptions() (ReportOptions, error) {
	var file struct {
		Traffic ReportOptions `toml:"traffic"`
	}
	if path := findConfigFile(); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return file.Traffic, err
		}
		if err = toml.Unmarshal(raw, &file); err != nil {
			return file.Traffic, fmt.Errorf("report_config_parse_failed")
		}
	}
	o := file.Traffic
	for _, pair := range []struct {
		name  string
		value *int
	}{
		{"REPORT_INPUT_TOKEN_LIMIT", &o.InputTokens}, {"REPORT_OUTPUT_TOKEN_LIMIT", &o.OutputTokens},
		{"REPORT_CONTEXT_WINDOW_TOKENS", &o.ContextTokens}, {"REPORT_TOKEN_SAFETY_MARGIN", &o.SafetyTokens}, {"REPORT_LOG_RETENTION_DAYS", &o.RetentionDays},
	} {
		if v, ok := os.LookupEnv(pair.name); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				return o, fmt.Errorf("invalid %s", pair.name)
			}
			*pair.value = n
		}
	}
	if v, ok := os.LookupEnv("REPORT_LOG_DIR"); ok {
		o.LogDir = v
	}
	if v, ok := os.LookupEnv("REPORT_LOG_ENABLED"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return o, fmt.Errorf("invalid REPORT_LOG_ENABLED")
		}
		o.LogEnabled = &b
	}
	return o, nil
}

func (o ReportOptions) Resolve(inheritedOutput int) (ReportOptions, error) {
	if o.InputTokens < 0 || o.OutputTokens < 0 || o.ContextTokens < 0 || o.SafetyTokens < 0 || o.RetentionDays < 0 {
		return o, fmt.Errorf("report_config_negative_limit")
	}
	if o.InputTokens == 0 {
		o.InputTokens = 20000
	} // full prompt incl. system; legacy user cap remains 18000
	if o.OutputTokens == 0 {
		o.OutputTokens = inheritedOutput
	}
	if o.OutputTokens <= 0 {
		o.OutputTokens = 6000
	}
	if o.ContextTokens > 0 && (o.InputTokens > o.ContextTokens || o.OutputTokens > o.ContextTokens-o.InputTokens || o.SafetyTokens > o.ContextTokens-o.InputTokens-o.OutputTokens) {
		return o, fmt.Errorf("report_config_context_budget_exceeded")
	}
	if o.LogDir == "" {
		o.LogDir = "data/repLogs"
	}
	if o.RetentionDays == 0 {
		o.RetentionDays = 30
	}
	return o, nil
}
