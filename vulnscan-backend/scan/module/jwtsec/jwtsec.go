package jwtsec

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/vulnkit"
)

type JWTSecScanner struct {
	base *vulnkit.VulnScanner
}

func New() *JWTSecScanner {
	return &JWTSecScanner{}
}

func (m *JWTSecScanner) ID() string       { return "jwt_sec" }
func (m *JWTSecScanner) Name() string     { return "JWT 安全检测" }
func (m *JWTSecScanner) Category() string { return "vuln" }

func (m *JWTSecScanner) Params() []core.ModuleParam {
	return []core.ModuleParam{core.VulnVerificationParam()}
}

func (m *JWTSecScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.base = vulnkit.NewVulnScanner(config)
	verifyLevel := core.GetConfigValue(config, "verification_level", "both")

	result := m.base.RunTargets(ctx, m.ID(), targets, func(ctx context.Context, target *core.Target) []*core.Finding {
		return m.testTarget(ctx, target, verifyLevel)
	})

	vulnkit.LogModuleComplete(m.ID(), len(targets), len(result.Findings), result.Duration)
	return result, nil
}

var jwtPattern = regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*`)

var weakSecrets = []string{
	"secret", "password", "123456", "admin", "key", "jwt_secret",
	"changeme", "test", "default", "token", "mysecret", "supersecret",
	"12345678", "qwerty", "abc123", "letmein", "password1",
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

type jwtPayload struct {
	Exp json.Number `json:"exp,omitempty"`
	Iat json.Number `json:"iat,omitempty"`
	Iss string      `json:"iss,omitempty"`
	Aud interface{} `json:"aud,omitempty"`
	Sub string      `json:"sub,omitempty"`
}

func (m *JWTSecScanner) testTarget(ctx context.Context, target *core.Target, verifyLevel string) []*core.Finding {
	resp, body := m.base.FetchFullResponse(ctx, target.URL)
	if body == "" {
		return nil
	}

	tokens := m.extractTokens(resp, body)
	if len(tokens) == 0 {
		return nil
	}

	var findings []*core.Finding

	for _, token := range tokens {
		if core.ShouldRunPrinciple(verifyLevel) {
			findings = append(findings, m.analyzeTokenStructure(target, token)...)
		}
		if core.ShouldRunExploit(verifyLevel) {
			if f := m.testAlgNone(ctx, target, token); f != nil {
				findings = append(findings, f)
			}
			if f := m.testWeakSecret(target, token); f != nil {
				findings = append(findings, f)
			}
			if f := m.testEmptySignature(ctx, target, token); f != nil {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (m *JWTSecScanner) extractTokens(resp *http.Response, body string) []string {
	seen := make(map[string]struct{})
	var tokens []string

	addToken := func(t string) {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			tokens = append(tokens, t)
		}
	}

	if resp != nil {
		for _, cookie := range resp.Cookies() {
			matches := jwtPattern.FindAllString(cookie.Value, 3)
			for _, match := range matches {
				addToken(match)
			}
		}

		for _, h := range []string{"Authorization", "X-Auth-Token", "X-Access-Token"} {
			val := resp.Header.Get(h)
			if val != "" {
				val = strings.TrimPrefix(val, "Bearer ")
				matches := jwtPattern.FindAllString(val, 3)
				for _, match := range matches {
					addToken(match)
				}
			}
		}
	}

	bodyMatches := jwtPattern.FindAllString(body, 10)
	for _, match := range bodyMatches {
		addToken(match)
	}

	return tokens
}

func decodeJWTPart(part string) ([]byte, error) {
	if m := len(part) % 4; m != 0 {
		part += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(part)
}

func (m *JWTSecScanner) analyzeTokenStructure(target *core.Target, token string) []*core.Finding {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 3 {
		return nil
	}

	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil
	}

	var payload jwtPayload
	dec := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil
	}

	var findings []*core.Finding

	if strings.EqualFold(header.Alg, "none") || header.Alg == "" {
		findings = append(findings, &core.Finding{
			ModuleID:           m.ID(),
			Target:             target,
			Type:               "jwt_alg_none",
			Title:              "JWT Algorithm None",
			Description:        "JWT token使用 alg:none，签名验证可能被绕过",
			Severity:           "critical",
			Confidence:         85,
			Evidence:           string(headerBytes),
			VerificationLevel:  core.VerifyPrinciple,
			VerificationDetail: "alg-none-detected",
			Timestamp:          time.Now(),
			Data: map[string]string{
				"alg":   header.Alg,
				"token": vulnkit.Truncate(token, 100),
				"type":  "jwt-alg-none",
			},
		})
	}

	if payload.Exp.String() == "" || payload.Exp.String() == "0" {
		findings = append(findings, &core.Finding{
			ModuleID:           m.ID(),
			Target:             target,
			Type:               "jwt_no_expiry",
			Title:              "JWT 无过期时间",
			Description:        "JWT token缺少 exp 字段，token永不过期",
			Severity:           "medium",
			Confidence:         80,
			Evidence:           string(payloadBytes),
			VerificationLevel:  core.VerifyPrinciple,
			VerificationDetail: "missing-expiration",
			Timestamp:          time.Now(),
			Data: map[string]string{
				"token": vulnkit.Truncate(token, 100),
				"type":  "jwt-no-expiry",
			},
		})
	} else {
		expInt, err := payload.Exp.Int64()
		if err == nil {
			expTime := time.Unix(expInt, 0)
			duration := time.Until(expTime)
			if duration > 30*24*time.Hour {
				findings = append(findings, &core.Finding{
					ModuleID:           m.ID(),
					Target:             target,
					Type:               "jwt_long_expiry",
					Title:              "JWT 过期时间过长",
					Description:        fmt.Sprintf("JWT token过期时间为 %s，超过30天", expTime.Format(time.RFC3339)),
					Severity:           "low",
					Confidence:         75,
					Evidence:           string(payloadBytes),
					VerificationLevel:  core.VerifyPrinciple,
					VerificationDetail: "excessive-expiration",
					Timestamp:          time.Now(),
					Data: map[string]string{
						"exp":      expTime.Format(time.RFC3339),
						"duration": duration.String(),
						"token":    vulnkit.Truncate(token, 100),
						"type":     "jwt-long-expiry",
					},
				})
			}
		}
	}

	return findings
}

func (m *JWTSecScanner) testWeakSecret(target *core.Target, token string) *core.Finding {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 3 {
		return nil
	}

	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

	if header.Alg != "HS256" && header.Alg != "HS384" && header.Alg != "HS512" {
		return nil
	}

	signingInput := parts[0] + "." + parts[1]

	for _, secret := range weakSecrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if expectedSig == parts[2] {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "jwt_weak_secret",
				Title:              "JWT 弱密钥",
				Description:        fmt.Sprintf("JWT token使用弱密钥 '%s' 签名，攻击者可伪造token", secret),
				Severity:           "critical",
				Confidence:         95,
				Evidence:           fmt.Sprintf("Secret: %s, Algorithm: %s", secret, header.Alg),
				VerificationLevel:  core.VerifyExploit,
				VerificationDetail: "weak-secret-cracked",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"secret": secret,
					"alg":    header.Alg,
					"token":  vulnkit.Truncate(token, 100),
					"type":   "jwt-weak-secret",
				},
			}
		}
	}

	return nil
}

func (m *JWTSecScanner) testAlgNone(ctx context.Context, target *core.Target, token string) *core.Finding {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 3 {
		return nil
	}

	noneHeaders := []string{
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"None","typ":"JWT"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"NONE","typ":"JWT"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"nOnE","typ":"JWT"}`)),
	}

	originalResp := m.sendWithToken(ctx, target.URL, token)

	for _, nh := range noneHeaders {
		forgedToken := nh + "." + parts[1] + "."

		forgedResp := m.sendWithToken(ctx, target.URL, forgedToken)
		if forgedResp == "" {
			continue
		}

		if isSuccessResponse(forgedResp) && isSuccessResponse(originalResp) && vulnkit.Similarity(originalResp, forgedResp) > 0.7 {
			return &core.Finding{
				ModuleID:           m.ID(),
				Target:             target,
				Type:               "jwt_alg_none_bypass",
				Title:              "JWT Algorithm None 绕过",
				Description:        "服务端接受了alg:none的JWT token，签名验证被完全绕过",
				Severity:           "critical",
				Confidence:         90,
				Evidence:           vulnkit.Truncate(forgedResp, 500),
				VerificationLevel:  core.VerifyExploit,
				VerificationDetail: "alg-none-bypass-confirmed",
				Timestamp:          time.Now(),
				Data: map[string]string{
					"forged_token": vulnkit.Truncate(forgedToken, 200),
					"type":         "jwt-alg-none-bypass",
				},
			}
		}
	}

	return nil
}

func (m *JWTSecScanner) testEmptySignature(ctx context.Context, target *core.Target, token string) *core.Finding {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 3 || parts[2] == "" {
		return nil
	}

	emptyToken := parts[0] + "." + parts[1] + "."

	originalResp := m.sendWithToken(ctx, target.URL, token)
	emptyResp := m.sendWithToken(ctx, target.URL, emptyToken)

	if emptyResp == "" || originalResp == "" {
		return nil
	}

	if isSuccessResponse(emptyResp) && isSuccessResponse(originalResp) && vulnkit.Similarity(originalResp, emptyResp) > 0.7 {
		return &core.Finding{
			ModuleID:           m.ID(),
			Target:             target,
			Type:               "jwt_empty_sig",
			Title:              "JWT 空签名接受",
			Description:        "服务端接受了空签名的JWT token，签名验证存在缺陷",
			Severity:           "critical",
			Confidence:         88,
			Evidence:           vulnkit.Truncate(emptyResp, 500),
			VerificationLevel:  core.VerifyExploit,
			VerificationDetail: "empty-signature-accepted",
			Timestamp:          time.Now(),
			Data: map[string]string{
				"type": "jwt-empty-signature",
			},
		}
	}

	return nil
}

func (m *JWTSecScanner) sendWithToken(ctx context.Context, rawURL, token string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	body, _, err := m.base.Client.Fetch(req)
	if err != nil {
		return ""
	}
	return body
}

func isSuccessResponse(body string) bool {
	lower := strings.ToLower(body)
	return !strings.Contains(lower, "unauthorized") &&
		!strings.Contains(lower, "invalid token") &&
		!strings.Contains(lower, "401") &&
		!strings.Contains(lower, "forbidden")
}
