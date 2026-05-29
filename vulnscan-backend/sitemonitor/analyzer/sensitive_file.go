package analyzer

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"
)

type SensitiveFileAnalyzer struct {
	rules RuleAccessor
}

func NewSensitiveFileAnalyzer(rules RuleAccessor) *SensitiveFileAnalyzer {
	return &SensitiveFileAnalyzer{rules: rules}
}

func (a *SensitiveFileAnalyzer) Dimension() string { return "sensitive_file" }

const sensitiveFileConcurrency = 10

func (a *SensitiveFileAnalyzer) Analyze(ctx context.Context, input *Input) (*Output, error) {
	baseURL := input.URL
	if baseURL == "" {
		return &Output{HasIssue: false}, nil
	}

	paths := a.loadProbePaths(input.Config)
	if len(paths) == 0 {
		paths = a.defaultProbePaths()
	}
	if len(paths) > 150 {
		paths = paths[:150]
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: sensitiveFileConcurrency,
			IdleConnTimeout:     30 * time.Second,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	type probeResult struct {
		finding model.MonitorSensitiveFileFinding
		hit     bool
		elapsed int
	}

	results := make([]probeResult, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, sensitiveFileConcurrency)

	for i, p := range paths {
		target, err := joinURL(baseURL, p.Path)
		if err != nil {
			continue
		}

		wg.Add(1)
		go func(idx int, pp probePath, targetURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "VulnScan-Monitor/1.0")

			resp, err := client.Do(req)
			elapsed := int(time.Since(start).Milliseconds())
			if err != nil {
				results[idx] = probeResult{elapsed: elapsed}
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()

			bodyStr := string(body)
			hitType := classifySensitiveFileHit(resp.StatusCode, len(body), bodyStr)
			if hitType == "" && !isDirectoryListing(bodyStr) {
				results[idx] = probeResult{elapsed: elapsed}
				return
			}

			risk := pp.Risk
			if risk == "" {
				risk = "high"
			}
			if hitType == "auth_required" && risk != "critical" {
				risk = "medium"
			}
			mark := pp.Mark
			if mark == "" {
				mark = "敏感路径"
			}
			if isDirectoryListing(bodyStr) && hitType == "" {
				hitType = "directory_listing"
				risk = "high"
				mark = "目录遍历"
			}

			var contentFingerprint string
			if hitType == "content_exposed" {
				contentFingerprint = classifyContentFingerprint(bodyStr, pp.Path)
			}

			detail := truncate(bodyStr, 200)
			if contentFingerprint != "" {
				detail = "[" + contentFingerprint + "] " + detail
			}

			results[idx] = probeResult{
				hit:     true,
				elapsed: elapsed,
				finding: model.MonitorSensitiveFileFinding{
					URL:           targetURL,
					Path:          pp.Path,
					Mark:          mark,
					Risk:          risk,
					StatusCode:    resp.StatusCode,
					ContentLength: len(body),
					Detail:        detail,
					ElapsedMs:     float64(elapsed),
				},
			}
		}(i, p, target)
	}
	wg.Wait()

	findings := make([]model.MonitorSensitiveFileFinding, 0)
	riskSummary := map[string]int{}
	totalMs := 0
	for _, r := range results {
		totalMs += r.elapsed
		if r.hit {
			findings = append(findings, r.finding)
			riskSummary[r.finding.Risk]++
		}
	}

	hasHit := len(findings) > 0
	detail := model.MonitorSensitiveFileResult{
		URL:      baseURL,
		HasHit:   hasHit,
		Findings: findings,
		Stats: model.MonitorSensitiveFileStats{
			TotalChecked:  len(paths),
			TotalFindings: len(findings),
			TotalProbeMs:  totalMs,
			RiskSummary:   riskSummary,
		},
	}
	raw, _ := json.Marshal(detail)
	out := &Output{HasIssue: hasHit}
	if hasHit {
		out.Severity = classifySensitiveFileSeverity(findings)
	}
	out.DetailsJSON = string(raw)
	return out, nil
}

func classifySensitiveFileSeverity(findings []model.MonitorSensitiveFileFinding) string {
	for _, f := range findings {
		if f.Risk == "critical" {
			return "critical"
		}
	}
	highCount := 0
	for _, f := range findings {
		if f.Risk == "high" {
			highCount++
		}
	}
	if highCount > 2 {
		return "critical"
	}
	if highCount > 0 {
		return "high"
	}
	return "medium"
}

type probePath struct {
	Path string
	Mark string
	Risk string
}

func (a *SensitiveFileAnalyzer) loadProbePaths(cfg map[string]any) []probePath {
	ids := extractConfigStringSlice(cfg, "file_library_ids")
	if len(ids) == 0 {
		return nil
	}
	paths := make([]probePath, 0)
	for _, id := range ids {
		key := "lib/file/" + id
		data, err := a.rules.GetModuleRules(key)
		if err != nil || len(data) == 0 {
			continue
		}
		var lib struct {
			Entries []struct {
				Path string `json:"path"`
				Mark string `json:"mark"`
				Risk string `json:"risk"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(data, &lib); err != nil {
			continue
		}
		for _, e := range lib.Entries {
			if e.Path == "" {
				continue
			}
			paths = append(paths, probePath{Path: e.Path, Mark: e.Mark, Risk: e.Risk})
		}
	}
	return paths
}

func (a *SensitiveFileAnalyzer) defaultProbePaths() []probePath {
	data, err := a.rules.GetModuleRules("sf_engine")
	if err != nil || len(data) == 0 {
		return []probePath{
			// 版本控制系统
			{Path: "/.git/HEAD", Mark: "Git泄露", Risk: "critical"},
			{Path: "/.git/config", Mark: "Git配置", Risk: "critical"},
			{Path: "/.git/index", Mark: "Git索引", Risk: "critical"},
			{Path: "/.svn/entries", Mark: "SVN泄露", Risk: "critical"},
			{Path: "/.svn/wc.db", Mark: "SVN数据库", Risk: "critical"},
			{Path: "/.hg/hgrc", Mark: "Mercurial配置", Risk: "critical"},
			// 环境/配置文件
			{Path: "/.env", Mark: "环境变量", Risk: "critical"},
			{Path: "/.env.local", Mark: "本地环境变量", Risk: "critical"},
			{Path: "/.env.production", Mark: "生产环境变量", Risk: "critical"},
			{Path: "/.env.backup", Mark: "环境变量备份", Risk: "critical"},
			{Path: "/web.config", Mark: "IIS配置", Risk: "high"},
			{Path: "/.htaccess", Mark: "Apache访问控制", Risk: "medium"},
			{Path: "/.htpasswd", Mark: "Apache密码", Risk: "critical"},
			// PHP
			{Path: "/phpinfo.php", Mark: "PHP信息", Risk: "high"},
			{Path: "/info.php", Mark: "PHP信息", Risk: "high"},
			{Path: "/wp-config.php.bak", Mark: "WordPress备份", Risk: "critical"},
			{Path: "/wp-config.php.old", Mark: "WordPress旧配置", Risk: "critical"},
			{Path: "/wp-config.php~", Mark: "WordPress配置备份", Risk: "critical"},
			{Path: "/composer.json", Mark: "PHP依赖", Risk: "medium"},
			// Java
			{Path: "/WEB-INF/web.xml", Mark: "Java配置泄露", Risk: "critical"},
			{Path: "/META-INF/MANIFEST.MF", Mark: "Java清单", Risk: "high"},
			// Spring
			{Path: "/actuator", Mark: "Spring Actuator", Risk: "high"},
			{Path: "/actuator/env", Mark: "Spring环境变量", Risk: "critical"},
			{Path: "/actuator/heapdump", Mark: "Spring堆转储", Risk: "critical"},
			{Path: "/actuator/configprops", Mark: "Spring配置属性", Risk: "critical"},
			// API文档
			{Path: "/swagger-ui.html", Mark: "Swagger文档", Risk: "medium"},
			{Path: "/swagger-ui/", Mark: "Swagger UI", Risk: "medium"},
			{Path: "/api-docs", Mark: "API文档", Risk: "medium"},
			{Path: "/graphiql", Mark: "GraphiQL IDE", Risk: "medium"},
			// 服务器状态
			{Path: "/server-status", Mark: "Apache状态", Risk: "high"},
			{Path: "/server-info", Mark: "Apache信息", Risk: "high"},
			{Path: "/nginx_status", Mark: "Nginx状态", Risk: "high"},
			// 数据库管理
			{Path: "/phpmyadmin/", Mark: "phpMyAdmin", Risk: "high"},
			{Path: "/adminer.php", Mark: "Adminer", Risk: "high"},
			// 备份/日志
			{Path: "/backup/", Mark: "备份目录", Risk: "high"},
			{Path: "/backups/", Mark: "备份目录", Risk: "high"},
			{Path: "/dump.sql", Mark: "SQL导出", Risk: "critical"},
			{Path: "/database.sql", Mark: "数据库导出", Risk: "critical"},
			{Path: "/db.sql", Mark: "数据库导出", Risk: "critical"},
			{Path: "/error.log", Mark: "错误日志", Risk: "high"},
			{Path: "/access.log", Mark: "访问日志", Risk: "medium"},
			// 文件索引
			{Path: "/.DS_Store", Mark: "Mac目录索引", Risk: "high"},
			{Path: "/Thumbs.db", Mark: "Windows缩略图", Risk: "medium"},
			// IDE
			{Path: "/.idea/workspace.xml", Mark: "JetBrains项目", Risk: "medium"},
			{Path: "/.vscode/settings.json", Mark: "VSCode配置", Risk: "medium"},
			// 上传/临时
			{Path: "/upload/", Mark: "上传目录", Risk: "medium"},
			{Path: "/uploads/", Mark: "上传目录", Risk: "medium"},
			{Path: "/temp/", Mark: "临时目录", Risk: "medium"},
			// 管理后台
			{Path: "/admin/", Mark: "管理后台", Risk: "medium"},
			{Path: "/administrator/", Mark: "Joomla后台", Risk: "medium"},
			{Path: "/console/", Mark: "控制台", Risk: "high"},
			// 容器/部署
			{Path: "/Dockerfile", Mark: "Docker构建", Risk: "medium"},
			{Path: "/docker-compose.yml", Mark: "Docker编排", Risk: "high"},
			{Path: "/.dockerenv", Mark: "Docker容器标识", Risk: "medium"},
			// .NET
			{Path: "/elmah.axd", Mark: ".NET错误日志", Risk: "high"},
			{Path: "/trace.axd", Mark: ".NET跟踪", Risk: "high"},
			// 其他
			{Path: "/robots.txt", Mark: "robots", Risk: "low"},
			{Path: "/crossdomain.xml", Mark: "跨域策略", Risk: "medium"},
			{Path: "/.well-known/security.txt", Mark: "安全联系", Risk: "low"},
			{Path: "/package.json", Mark: "Node.js依赖", Risk: "medium"},
		}
	}
	var engine struct {
		HighRiskDirs []struct {
			Path string `json:"path"`
		} `json:"high_risk_dirs"`
		FrameworkPaths []struct {
			Path      string `json:"path"`
			Mark      string `json:"mark"`
			Risk      string `json:"risk"`
			Framework string `json:"framework"`
		} `json:"framework_paths"`
	}
	if err := json.Unmarshal(data, &engine); err != nil {
		return nil
	}
	out := make([]probePath, 0, len(engine.HighRiskDirs)+len(engine.FrameworkPaths))
	for _, d := range engine.HighRiskDirs {
		if d.Path != "" {
			out = append(out, probePath{Path: d.Path, Mark: "高风险目录", Risk: "high"})
		}
	}
	for _, fp := range engine.FrameworkPaths {
		if fp.Path == "" {
			continue
		}
		mark := fp.Mark
		if mark == "" {
			mark = fp.Framework
		}
		risk := fp.Risk
		if risk == "" {
			risk = "medium"
		}
		out = append(out, probePath{Path: fp.Path, Mark: mark, Risk: risk})
	}
	return out
}

func extractConfigStringSlice(cfg map[string]any, key string) []string {
	if cfg == nil {
		return nil
	}
	v, ok := cfg[key]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func joinURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return u.ResolveReference(ref).String(), nil
}

func classifySensitiveFileHit(status int, bodyLen int, body string) string {
	if status == http.StatusOK && bodyLen > 0 {
		if isWAFBlockPage(body) {
			return ""
		}
		return "content_exposed"
	}
	if status == http.StatusForbidden || status == http.StatusUnauthorized {
		return "auth_required"
	}
	return ""
}

var wafBlockPatterns = []string{
	"access denied",
	"request denied",
	"forbidden",
	"blocked by",
	"waf",
	"firewall",
	"security policy",
	"不允许访问",
	"访问被拒绝",
	"请求被拦截",
}

func isWAFBlockPage(body string) bool {
	lower := strings.ToLower(body)
	if len(body) > 2000 {
		return false
	}
	matchCount := 0
	for _, pattern := range wafBlockPatterns {
		if strings.Contains(lower, pattern) {
			matchCount++
		}
	}
	return matchCount >= 2
}

func isDirectoryListing(body string) bool {
	lower := strings.ToLower(body)
	indicators := 0
	if strings.Contains(lower, "index of") || strings.Contains(lower, "directory listing") {
		indicators += 2
	}
	if strings.Contains(lower, "parent directory") || strings.Contains(lower, "上级目录") {
		indicators++
	}
	if strings.Contains(lower, "<pre>") && strings.Contains(lower, "href=") {
		indicators++
	}
	if strings.Count(lower, "href=") > 5 && (strings.Contains(lower, "last modified") || strings.Contains(lower, "size")) {
		indicators++
	}
	return indicators >= 2
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var contentFingerprintRules = []struct {
	pattern  string
	category string
}{
	// 数据库凭证
	{"DB_PASSWORD", "数据库凭证"},
	{"DB_HOST", "数据库凭证"},
	{"DATABASE_URL", "数据库凭证"},
	{"MYSQL_", "数据库凭证"},
	{"POSTGRES_", "数据库凭证"},
	{"MONGO_URI", "数据库凭证"},
	{"REDIS_", "缓存凭证"},
	{"REDIS_PASSWORD", "缓存凭证"},
	{"MEMCACHED_", "缓存凭证"},
	// 密钥/令牌
	{"SECRET_KEY", "密钥"},
	{"API_KEY", "API密钥"},
	{"ACCESS_KEY", "云凭证"},
	{"AWS_", "AWS凭证"},
	{"PRIVATE_KEY", "私钥"},
	{"-----BEGIN", "证书/密钥"},
	{"JWT_SECRET", "JWT密钥"},
	{"ENCRYPTION_KEY", "加密密钥"},
	// 第三方服务
	{"STRIPE_", "Stripe支付"},
	{"PAYPAL_", "PayPal支付"},
	{"TWILIO_", "Twilio凭证"},
	{"SENDGRID_", "SendGrid凭证"},
	{"SLACK_", "Slack凭证"},
	{"GITHUB_TOKEN", "GitHub Token"},
	{"GITLAB_TOKEN", "GitLab Token"},
	{"OPENAI_API", "OpenAI密钥"},
	// 云厂商
	{"ALICLOUD_", "阿里云凭证"},
	{"TENCENTCLOUD_", "腾讯云凭证"},
	{"HUAWEICLOUD_", "华为云凭证"},
	{"AZURE_", "Azure凭证"},
	{"GCP_", "GCP凭证"},
	{"GOOGLE_APPLICATION_CREDENTIALS", "GCP服务账号"},
	// 版本控制
	{"ref: refs/heads/", "Git HEAD"},
	{"[core]", "Git配置"},
	{"[remote", "Git配置"},
	// PHP
	{"phpinfo()", "PHP信息泄露"},
	{"PHP Version", "PHP信息泄露"},
	{"PHP License", "PHP信息泄露"},
	// 服务器
	{"SERVER_SOFTWARE", "服务器信息"},
	{"DOCUMENT_ROOT", "服务器路径"},
	{"SERVER_ADMIN", "管理员邮箱"},
	// WordPress
	{"wp-config", "WordPress配置"},
	{"define('DB_", "WordPress数据库"},
	{"AUTH_KEY", "WordPress密钥"},
	{"NONCE_KEY", "WordPress密钥"},
	// Spring/Java
	{"spring.datasource", "Spring数据源"},
	{"spring.redis", "Spring Redis"},
	{"server.port", "Spring端口配置"},
	{"jdbc:", "JDBC连接串"},
	// Docker/K8s
	{"DOCKER_HOST", "Docker配置"},
	{"KUBERNETES_", "K8s配置"},
	// 邮件
	{"SMTP_PASSWORD", "邮件凭证"},
	{"MAIL_PASSWORD", "邮件凭证"},
	{"EMAIL_HOST_PASSWORD", "邮件凭证"},
	// 消息队列
	{"RABBITMQ_", "RabbitMQ凭证"},
	{"KAFKA_", "Kafka配置"},
	// Spring Actuator
	{"\"spring.datasource", "Spring环境泄露"},
	{"\"management.endpoints", "Spring管理端点"},
	// 数据库导出特征
	{"INSERT INTO", "SQL导出"},
	{"CREATE TABLE", "SQL导出"},
	{"mysqldump", "MySQL导出"},
	{"pg_dump", "PostgreSQL导出"},
}

func classifyContentFingerprint(body, path string) string {
	upper := strings.ToUpper(body)
	for _, rule := range contentFingerprintRules {
		if strings.Contains(upper, strings.ToUpper(rule.pattern)) {
			return rule.category
		}
	}

	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, ".env"):
		return "环境变量"
	case strings.Contains(lower, ".git"):
		return "Git泄露"
	case strings.Contains(lower, "backup") || strings.Contains(lower, ".bak"):
		return "备份文件"
	case strings.Contains(lower, "config"):
		return "配置文件"
	case strings.Contains(lower, ".sql"):
		return "数据库导出"
	case strings.Contains(lower, ".log"):
		return "日志文件"
	}
	return ""
}
