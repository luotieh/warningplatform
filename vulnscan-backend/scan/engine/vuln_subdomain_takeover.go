package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SubdomainTakeoverScannerModule struct {
	scanner *VulnScanner
}

func NewSubdomainTakeoverScannerModule(scanner *VulnScanner) *SubdomainTakeoverScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "subdomain-takeover-scanner"})
	}
	return &SubdomainTakeoverScannerModule{scanner: scanner}
}

func (m *SubdomainTakeoverScannerModule) ID() string       { return "subdomain-takeover-scanner" }
func (m *SubdomainTakeoverScannerModule) Name() string     { return "Subdomain Takeover Scanner" }
func (m *SubdomainTakeoverScannerModule) Category() string { return "web" }

func (m *SubdomainTakeoverScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		if target.URL == "" && target.Host != "" {
			target.URL = fmt.Sprintf("http://%s", target.Host)
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t *Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.scanTarget(ctx, t)
			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[SubdomainTakeover-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *SubdomainTakeoverScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	if target.Host == "" {
		return findings
	}

	cname, err := net.LookupCNAME(target.Host)
	if err != nil {
		return findings
	}

	if cname == "" {
		return findings
	}

	for _, pattern := range takeoverPatterns {
		if strings.Contains(strings.ToLower(cname), pattern.service) {
			body, statusCode, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, target.URL))
			if err != nil {
				continue
			}

			if m.isTakeoverPage(statusCode, body, pattern) {
				findings = append(findings, &Finding{
					Target:      target,
					Type:        "subdomain_takeover",
					Title:       fmt.Sprintf("Potential Subdomain Takeover - %s", pattern.service),
					Description: fmt.Sprintf("The subdomain %s has a CNAME pointing to %s which appears to be unclaimed", target.Host, cname),
					Severity:    "high",
					Confidence:  80,
					Evidence:    fmt.Sprintf("CNAME: %s, Response: %s", cname, body[:min(200, len(body))]),
					Timestamp:   time.Now(),
					Remediation: "Claim the service or remove the DNS record",
					Data: map[string]string{
						"cname":   cname,
						"service": pattern.service,
					},
				})
			}
		}
	}

	return findings
}

type takeoverPattern struct {
	service      string
	fingerprints []string
}

var takeoverPatterns = []takeoverPattern{
	{
		service:      "github",
		fingerprints: []string{"There isn't a GitHub Pages site here", "For root URLs, please make sure you have added a CNAME file"},
	},
	{
		service:      "heroku",
		fingerprints: []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"},
	},
	{
		service:      "shopify",
		fingerprints: []string{"Sorry, this shop is closed", "shopify.com"},
	},
	{
		service:      "aws_s3",
		fingerprints: []string{"NoSuchBucket", "The specified bucket does not exist", "All access to this object has been disabled"},
	},
	{
		service:      "azure",
		fingerprints: []string{"404 Web Site not found", "azurewebsites.net"},
	},
	{
		service:      "bitbucket",
		fingerprints: []string{"The page you have requested does not exist", "Bitbucket"},
	},
	{
		service:      "wordpress",
		fingerprints: []string{"Do you want to register", "wordpress.com"},
	},
	{
		service:      "zendesk",
		fingerprints: []string{"Help Center Closed", "zendesk.com"},
	},
	{
		service:      "ghost",
		fingerprints: []string{"The thing you were looking for is no longer here", "ghost.org"},
	},
	{
		service:      "tumblr",
		fingerprints: []string{"There's nothing here", "tumblr.com"},
	},
}

func (m *SubdomainTakeoverScannerModule) isTakeoverPage(statusCode int, body string, pattern takeoverPattern) bool {
	bodyLower := strings.ToLower(body)

	for _, fp := range pattern.fingerprints {
		if strings.Contains(bodyLower, strings.ToLower(fp)) {
			return true
		}
	}

	return false
}

func (m *SubdomainTakeoverScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
