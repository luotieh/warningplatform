package vulnkit

import (
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/scanhttp"

	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var dynamicContentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{10,13}`),
	regexp.MustCompile(`[a-f0-9]{32}`),
	regexp.MustCompile(`csrf[_-]?token["']?\s*[:=]\s*["'][a-zA-Z0-9]+["']`),
	regexp.MustCompile(`_nonce["']?\s*[:=]\s*["'][a-zA-Z0-9]+["']`),
}

type Verifier struct {
	client     *http.Client
	strategies map[string]VerifyStrategy
}

type VerifyStrategy interface {
	Verify(ctx context.Context, finding *core.Finding) *VerifyResult
}

type VerifyResult struct {
	Verified   bool   `json:"verified"`
	Confidence int    `json:"confidence"`
	Detail     string `json:"detail"`
	Variants   int    `json:"variants_tested"`
	Confirmed  int    `json:"variants_confirmed"`
}

func NewVerifier() *Verifier {
	pool := scanhttp.GetGlobalClientPool()
	client := pool.GetOrCreate("verifier", scanhttp.WithRedirectPolicy(scanhttp.RedirectNoFollow), scanhttp.WithTimeout(15*time.Second))

	v := &Verifier{
		client:     client.RawClient(),
		strategies: make(map[string]VerifyStrategy),
	}
	v.strategies["sqli_error"] = &sqliErrorVerifier{client: client.RawClient()}
	v.strategies["sqli_boolean"] = &sqliBoolVerifier{client: client.RawClient()}
	v.strategies["sqli_time"] = &sqliTimeVerifier{client: client.RawClient()}
	v.strategies["sqli_union"] = &sqliUnionVerifier{client: client.RawClient()}
	v.strategies["xss_reflected"] = &xssReflectedVerifier{client: client.RawClient()}
	v.strategies["cmdi_time"] = &cmdiTimeVerifier{client: client.RawClient()}
	v.strategies["cmdi_output"] = &cmdiOutputVerifier{client: client.RawClient()}
	v.strategies["lfi"] = &lfiVerifier{client: client.RawClient()}

	return v
}

const perFindingVerifyTimeout = 30 * time.Second

func (v *Verifier) VerifyFindings(ctx context.Context, findings []*core.Finding) []*core.Finding {
	verified := make([]*core.Finding, 0, len(findings))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for _, f := range findings {
		strategy, ok := v.strategies[f.Type]
		if !ok {
			mu.Lock()
			verified = append(verified, f)
			mu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(finding *core.Finding, strat VerifyStrategy) {
			defer wg.Done()
			defer func() { <-sem }()

			verifyCtx, cancel := context.WithTimeout(ctx, perFindingVerifyTimeout)
			defer cancel()

			result := strat.Verify(verifyCtx, finding)

			if finding.Data == nil {
				finding.Data = make(map[string]string)
			}

			mu.Lock()
			defer mu.Unlock()

			if result.Verified {
				finding.Confidence = result.Confidence
				finding.Data["verified"] = "true"
				finding.Data["verify_detail"] = result.Detail
				finding.Data["verify_variants"] = fmt.Sprintf("%d/%d", result.Confirmed, result.Variants)
				verified = append(verified, finding)
				slog.Info("[Verifier] 漏洞已验证",
					"type", finding.Type, "target", finding.Target.Host,
					"confidence", result.Confidence,
				)
			} else {
				slog.Info("[Verifier] 漏洞未通过验证，降级",
					"type", finding.Type, "target", finding.Target.Host,
				)
				finding.Confidence = finding.Confidence / 2
				finding.Data["verified"] = "false"
				finding.Data["verify_detail"] = result.Detail
				verified = append(verified, finding)
			}
		}(f, strategy)
	}

	wg.Wait()
	return verified
}

type sqliErrorVerifier struct{ client *http.Client }

func (v *sqliErrorVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	param := f.Data["param"]
	if param == "" || f.Target == nil || f.Target.URL == "" {
		return &VerifyResult{Verified: false, Detail: "missing context"}
	}

	variants := []string{
		`'`,
		`1'`,
		`"`,
		`\`,
		`' AND '1'='1`,
	}

	confirmed := 0
	for _, payload := range variants {
		body := fetchWithPayload(ctx, v.client, f.Target.URL, param, payload)
		if hasDBError(body) {
			confirmed++
		}
	}

	return &VerifyResult{
		Verified:   confirmed >= 2,
		Confidence: min(95, f.Confidence+confirmed*5),
		Detail:     fmt.Sprintf("%d/%d variants triggered DB errors", confirmed, len(variants)),
		Variants:   len(variants),
		Confirmed:  confirmed,
	}
}

type sqliBoolVerifier struct{ client *http.Client }

func (v *sqliBoolVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	param := f.Data["param"]
	if param == "" || f.Target == nil || f.Target.URL == "" {
		return &VerifyResult{Verified: false, Detail: "missing context"}
	}

	baseBody := fetchBody(ctx, v.client, f.Target.URL)
	baseLines := extractLines(baseBody)

	pairs := []struct{ t, f string }{
		{`1 OR 1=1`, `1 OR 1=2`},
		{`' OR '1'='1`, `' OR '1'='2`},
		{`1) OR (1=1`, `1) OR (1=2`},
	}

	confirmed := 0
	for _, p := range pairs {
		tBody := fetchWithPayload(ctx, v.client, f.Target.URL, param, p.t)
		fBody := fetchWithPayload(ctx, v.client, f.Target.URL, param, p.f)
		if tBody != "" && fBody != "" {
			tLines := extractLines(tBody)
			fLines := extractLines(fBody)
			tJaccard := jaccardSimilarity(baseLines, tLines)
			fJaccard := jaccardSimilarity(baseLines, fLines)
			if tJaccard > 0.7 && fJaccard < 0.5 {
				confirmed++
			}
		}
	}

	return &VerifyResult{
		Verified:   confirmed >= 2,
		Confidence: min(90, f.Confidence+confirmed*5),
		Detail:     fmt.Sprintf("%d/%d boolean pairs confirmed", confirmed, len(pairs)),
		Variants:   len(pairs),
		Confirmed:  confirmed,
	}
}

type sqliTimeVerifier struct{ client *http.Client }

func (v *sqliTimeVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	param := f.Data["param"]
	if param == "" || f.Target == nil || f.Target.URL == "" {
		return &VerifyResult{Verified: false, Detail: "missing context"}
	}

	delays := []struct {
		payload string
		expect  time.Duration
	}{
		{`' OR SLEEP(3)-- `, 2500 * time.Millisecond},
		{`'; WAITFOR DELAY '0:0:3'-- `, 2500 * time.Millisecond},
		{`' || PG_SLEEP(3)-- `, 2500 * time.Millisecond},
	}

	confirmed := 0
	for _, d := range delays {
		start := time.Now()
		fetchWithPayload(ctx, v.client, f.Target.URL, param, d.payload)
		elapsed := time.Since(start)
		if elapsed >= d.expect {
			confirmed++
		}
	}

	return &VerifyResult{
		Verified:   confirmed >= 1,
		Confidence: min(95, f.Confidence+confirmed*10),
		Detail:     fmt.Sprintf("%d/%d time delays confirmed", confirmed, len(delays)),
		Variants:   len(delays),
		Confirmed:  confirmed,
	}
}

type sqliUnionVerifier struct{ client *http.Client }

func (v *sqliUnionVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	return &VerifyResult{
		Verified:   true,
		Confidence: f.Confidence,
		Detail:     "UNION injection auto-verified at detection",
		Variants:   1,
		Confirmed:  1,
	}
}

type xssReflectedVerifier struct{ client *http.Client }

func (v *xssReflectedVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	param := f.Data["param"]
	if param == "" || f.Target == nil || f.Target.URL == "" {
		return &VerifyResult{Verified: false, Detail: "missing context"}
	}

	probes := []struct {
		payload string
		expect  string
		context string
	}{
		{`<img src=x onerror=1>`, `onerror=1`, "html_tag"},
		{`<svg/onload=1>`, `onload=1`, "html_tag"},
		{`"><script>1</script>`, `<script>1</script>`, "script"},
		{`' onmouseover='alert(1)`, `onmouseover=`, "attribute"},
		{`javascript:alert(1)`, `javascript:alert(1)`, "javascript_uri"},
	}

	confirmed := 0
	executableContext := 0
	for _, p := range probes {
		body := fetchWithPayload(ctx, v.client, f.Target.URL, param, p.payload)
		if strings.Contains(body, p.expect) {
			confirmed++
			if isExecutableContext(body, p.expect, p.context) {
				executableContext++
			}
		}
	}

	detail := fmt.Sprintf("%d/%d XSS probes reflected", confirmed, len(probes))
	if executableContext > 0 {
		detail += fmt.Sprintf(", %d in executable context", executableContext)
	}

	return &VerifyResult{
		Verified:   confirmed >= 1,
		Confidence: min(95, f.Confidence+confirmed*5+executableContext*10),
		Detail:     detail,
		Variants:   len(probes),
		Confirmed:  confirmed,
	}
}

func isExecutableContext(body, payload, contextType string) bool {
	idx := strings.Index(body, payload)
	if idx == -1 {
		return false
	}

	before := body[:idx]

	switch contextType {
	case "script":
		scriptOpen := strings.Count(before, "<script")
		scriptClose := strings.Count(before, "</script>")
		return scriptOpen > scriptClose
	case "html_tag":
		lastTagStart := strings.LastIndex(before, "<")
		lastTagEnd := strings.LastIndex(before, ">")
		return lastTagStart > lastTagEnd
	case "attribute":
		lastQuote := strings.LastIndexAny(before, `"'`)
		if lastQuote == -1 {
			return false
		}
		lastTagStart := strings.LastIndex(before[:lastQuote], "<")
		return lastTagStart != -1
	case "javascript_uri":
		return strings.Contains(before, "href=") || strings.Contains(before, "src=")
	}

	return false
}

type cmdiTimeVerifier struct{ client *http.Client }

func (v *cmdiTimeVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	param := f.Data["param"]
	if param == "" || f.Target == nil || f.Target.URL == "" {
		return &VerifyResult{Verified: false, Detail: "missing context"}
	}

	start := time.Now()
	fetchWithPayload(ctx, v.client, f.Target.URL, param, "; sleep 3")
	elapsed := time.Since(start)

	verified := elapsed >= 2500*time.Millisecond

	return &VerifyResult{
		Verified:   verified,
		Confidence: min(95, f.Confidence+10),
		Detail:     fmt.Sprintf("sleep(3) verification: %v", elapsed.Round(time.Millisecond)),
		Variants:   1,
		Confirmed:  boolToInt(verified),
	}
}

type cmdiOutputVerifier struct{ client *http.Client }

func (v *cmdiOutputVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	return &VerifyResult{
		Verified:   true,
		Confidence: f.Confidence,
		Detail:     "Output-based CMDi auto-verified at detection",
		Variants:   1,
		Confirmed:  1,
	}
}

type lfiVerifier struct{ client *http.Client }

func (v *lfiVerifier) Verify(ctx context.Context, f *core.Finding) *VerifyResult {
	param := f.Data["param"]
	if param == "" || f.Target == nil || f.Target.URL == "" {
		return &VerifyResult{Verified: false, Detail: "missing context"}
	}

	probes := []struct {
		payload  string
		evidence string
	}{
		{"../../../../etc/passwd", "root:x:0:0"},
		{"....//....//....//etc/passwd", "root:x:0:0"},
		{"/proc/self/environ", "PATH="},
	}

	confirmed := 0
	for _, p := range probes {
		body := fetchWithPayload(ctx, v.client, f.Target.URL, param, p.payload)
		if strings.Contains(body, p.evidence) {
			confirmed++
		}
	}

	return &VerifyResult{
		Verified:   confirmed >= 1,
		Confidence: min(95, f.Confidence+confirmed*5),
		Detail:     fmt.Sprintf("%d/%d LFI probes succeeded", confirmed, len(probes)),
		Variants:   len(probes),
		Confirmed:  confirmed,
	}
}

func fetchWithPayload(ctx context.Context, client *http.Client, rawURL, param, payload string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	return fetchBody(ctx, client, parsed.String())
}

func fetchBody(ctx context.Context, client *http.Client, rawURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return string(body)
}

func hasDBError(body string) bool {
	lower := strings.ToLower(body)
	patterns := []string{
		"sql syntax", "mysql", "postgresql", "ora-", "sqlite",
		"sqlstate", "unclosed quotation", "odbc", "syntax error",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func extractLines(s string) map[string]struct{} {
	lines := make(map[string]struct{})
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			line = filterDynamicContent(line)
			if len(line) > 3 {
				lines[line] = struct{}{}
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		line = filterDynamicContent(line)
		if len(line) > 3 {
			lines[line] = struct{}{}
		}
	}
	return lines
}

func filterDynamicContent(s string) string {
	for _, pattern := range dynamicContentPatterns {
		s = pattern.ReplaceAllString(s, "<DYNAMIC>")
	}
	return s
}

func jaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	intersection := 0
	for line := range a {
		if _, ok := b[line]; ok {
			intersection++
		}
	}

	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func simpleRatio(a, b string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	la := len(a)
	lb := len(b)
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	return 1.0 - float64(diff)/float64(maxLen)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
