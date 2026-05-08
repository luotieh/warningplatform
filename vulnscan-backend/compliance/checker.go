package compliance

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Collector interface {
	Name() string
	Execute(ctx context.Context, target string, config CheckConfig) (string, error)
}

type CheckEngine struct {
	collectors map[string]Collector
}

func NewCheckEngine() *CheckEngine {
	return &CheckEngine{
		collectors: map[string]Collector{
			CheckTypeCommand: &CommandCollector{},
			CheckTypeFile:    &FileCollector{},
			CheckTypeAPI:     &APICollector{},
		},
	}
}

func (e *CheckEngine) RegisterCollector(checkType string, c Collector) {
	e.collectors[checkType] = c
}

func (e *CheckEngine) RunFramework(ctx context.Context, fw *Framework, targetID string) *ComplianceReport {
	report := &ComplianceReport{
		FrameworkID: fw.ID,
		TargetID:    targetID,
		TotalRules:  len(fw.Rules),
		GeneratedAt: time.Now(),
	}

	for _, rule := range fw.Rules {
		select {
		case <-ctx.Done():
			report.SkippedRules++
			report.Results = append(report.Results, CheckResult{
				RuleID:    rule.ID,
				TargetID:  targetID,
				Status:    StatusSkip,
				CheckedAt: time.Now(),
			})
			continue
		default:
		}

		result := e.checkRule(ctx, rule, targetID)
		report.Results = append(report.Results, result)

		switch result.Status {
		case StatusPass:
			report.PassedRules++
		case StatusFail:
			report.FailedRules++
		default:
			report.SkippedRules++
		}
	}

	if report.TotalRules > 0 {
		report.Score = float64(report.PassedRules) / float64(report.TotalRules) * 100
	}

	slog.Info("[+] 合规检查完成",
		"framework", fw.Name,
		"target", targetID,
		"score", fmt.Sprintf("%.1f%%", report.Score),
		"pass", report.PassedRules,
		"fail", report.FailedRules,
	)

	return report
}

func (e *CheckEngine) checkRule(ctx context.Context, rule Rule, targetID string) CheckResult {
	result := CheckResult{
		RuleID:    rule.ID,
		TargetID:  targetID,
		Expected:  rule.CheckConfig.Expected,
		CheckedAt: time.Now(),
	}

	collector, ok := e.collectors[rule.CheckType]
	if !ok {
		result.Status = StatusSkip
		result.Evidence = fmt.Sprintf("无可用收集器: %s", rule.CheckType)
		return result
	}

	actual, err := collector.Execute(ctx, targetID, rule.CheckConfig)
	if err != nil {
		result.Status = StatusError
		result.Evidence = fmt.Sprintf("收集失败: %v", err)
		return result
	}

	result.Actual = actual
	result.Status = evaluate(actual, rule.CheckConfig)
	result.Evidence = fmt.Sprintf("实际值: %s, 期望值: %s (%s)", actual, rule.CheckConfig.Expected, rule.CheckConfig.Comparator)

	return result
}

func evaluate(actual string, config CheckConfig) string {
	expected := config.Expected
	comp := config.Comparator

	switch comp {
	case ComparatorEqual:
		if strings.TrimSpace(actual) == strings.TrimSpace(expected) {
			return StatusPass
		}
		return StatusFail

	case ComparatorContains:
		if strings.Contains(actual, expected) {
			return StatusPass
		}
		return StatusFail

	case ComparatorRegex:
		re, err := regexp.Compile(expected)
		if err != nil {
			return StatusError
		}
		if re.MatchString(actual) {
			return StatusPass
		}
		return StatusFail

	case ComparatorGTE:
		av, err1 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
		ev, err2 := strconv.ParseFloat(expected, 64)
		if err1 != nil || err2 != nil {
			return StatusError
		}
		if av >= ev {
			return StatusPass
		}
		return StatusFail

	case ComparatorLTE:
		av, err1 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
		ev, err2 := strconv.ParseFloat(expected, 64)
		if err1 != nil || err2 != nil {
			return StatusError
		}
		if av <= ev {
			return StatusPass
		}
		return StatusFail

	case ComparatorNotEmpty:
		if strings.TrimSpace(actual) != "" {
			return StatusPass
		}
		return StatusFail

	case ComparatorEmpty:
		if strings.TrimSpace(actual) == "" {
			return StatusPass
		}
		return StatusFail

	default:
		return StatusError
	}
}

type SSHCredentials struct {
	Username string
	Password string
	Port     int
}

type CommandCollector struct {
	Creds SSHCredentials
}

func (c *CommandCollector) Name() string { return "command" }

func (c *CommandCollector) Execute(ctx context.Context, target string, config CheckConfig) (string, error) {
	if config.Command == "" {
		return "", fmt.Errorf("未指定命令")
	}

	port := c.Creds.Port
	if port <= 0 {
		port = 22
	}

	sshConfig := &ssh.ClientConfig{
		User: c.Creds.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Creds.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(target, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return "", fmt.Errorf("SSH连接失败 %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建SSH会话失败: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(config.Command); err != nil {
		if stderr.Len() > 0 {
			return stderr.String(), nil
		}
		return stdout.String(), nil
	}

	return strings.TrimSpace(stdout.String()), nil
}

type FileCollector struct {
	Creds SSHCredentials
}

func (c *FileCollector) Name() string { return "file" }

func (c *FileCollector) Execute(ctx context.Context, target string, config CheckConfig) (string, error) {
	if config.FilePath == "" {
		return "", fmt.Errorf("未指定文件路径")
	}

	port := c.Creds.Port
	if port <= 0 {
		port = 22
	}

	sshConfig := &ssh.ClientConfig{
		User: c.Creds.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Creds.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(target, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return "", fmt.Errorf("SSH连接失败 %s: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建SSH会话失败: %w", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	session.Stdout = &stdout

	cmd := fmt.Sprintf("cat %s 2>/dev/null", config.FilePath)
	if config.FileMatch != "" {
		cmd = fmt.Sprintf("grep -E '%s' %s 2>/dev/null", config.FileMatch, config.FilePath)
	}

	_ = session.Run(cmd)
	return strings.TrimSpace(stdout.String()), nil
}

type APICollector struct {
	client *http.Client
}

func (c *APICollector) Name() string { return "api" }

func (c *APICollector) Execute(ctx context.Context, target string, config CheckConfig) (string, error) {
	if config.APIPath == "" {
		return "", fmt.Errorf("未指定API路径")
	}

	if c.client == nil {
		c.client = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	url := fmt.Sprintf("http://%s%s", target, config.APIPath)
	if strings.HasPrefix(config.APIPath, "http") {
		url = config.APIPath
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	return strings.TrimSpace(string(body)), nil
}
