package scanner

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"vulnscan-backend/agent"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scanrunner"

	"code.yt-security.com/public/scanengine/core"
	"code.yt-security.com/public/scanengine/module/certcheck"
	"code.yt-security.com/public/scanengine/module/dirscan"
	"code.yt-security.com/public/scanengine/module/dnsall"
	"code.yt-security.com/public/scanengine/module/favicon"
	"code.yt-security.com/public/scanengine/module/icmp"
	"code.yt-security.com/public/scanengine/module/infoleak"
	"code.yt-security.com/public/scanengine/module/portscan"
	"code.yt-security.com/public/scanengine/module/serviceprobe"
	"code.yt-security.com/public/scanengine/module/sqli"
	"code.yt-security.com/public/scanengine/module/ssrf"
	"code.yt-security.com/public/scanengine/module/weakpass"
	"code.yt-security.com/public/scanengine/module/webcrawl"
	"code.yt-security.com/public/scanengine/module/xss"
)

type ScanPayload struct {
	TaskID     string                 `json:"task_id"`
	Targets    []string               `json:"targets"`
	Type       string                 `json:"type"`
	Config     map[string]interface{} `json:"config"`
	Parameters map[string]interface{} `json:"parameters"`
}

type ScanResult struct {
	TaskID          string                `json:"task_id"`
	Status          string                `json:"status"`
	Progress        float64               `json:"progress"`
	Vulnerabilities []model.Vulnerability `json:"vulnerabilities,omitempty"`
	Error           string                `json:"error,omitempty"`
}

type Executor struct {
	rawLoader *payload.Loader
	loader    *scanrunner.PayloadAdapter
}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) Type() string { return "scan" }

func (e *Executor) Init(_ context.Context) error {
	e.rawLoader = payload.NewLoader(nil)
	_ = e.rawLoader.LoadAll()
	e.loader = scanrunner.NewPayloadAdapter(e.rawLoader)
	return nil
}

func (e *Executor) Execute(ctx context.Context, rawPayload json.RawMessage) *agent.TaskResult {
	var p ScanPayload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return &agent.TaskResult{
			Status:     "failed",
			Error:      "invalid scan payload: " + err.Error(),
			StartedAt:  time.Now().UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}

	result := &agent.TaskResult{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}

	slog.Info("scan exec", "task_id", p.TaskID, "targets", len(p.Targets))

	var targets []*core.Target
	for _, addr := range p.Targets {
		targets = append(targets, &core.Target{Host: addr})
	}

	modules := e.resolveModules(p.Type, p.Config)
	config := make(map[string]interface{})
	for k, v := range p.Parameters {
		config[k] = v
	}

	var allFindings []*core.Finding

	for _, mod := range modules {
		select {
		case <-ctx.Done():
			result.Status = model.TaskStatusCancelled
			result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
			return result
		default:
		}

		modCtx, modCancel := context.WithTimeout(ctx, 10*time.Minute)
		modResult, err := mod.Run(modCtx, targets, config)
		modCancel()

		if err != nil {
			slog.Warn("module failed", "module", mod.ID(), "error", err)
			continue
		}

		allFindings = append(allFindings, modResult.Findings...)

		if modResult.Targets != nil {
			seen := make(map[string]struct{})
			for _, t := range targets {
				seen[t.Host+"|"+t.IP+"|"+t.URL] = struct{}{}
			}
			for _, t := range modResult.Targets {
				key := t.Host + "|" + t.IP + "|" + t.URL
				if _, ok := seen[key]; !ok {
					targets = append(targets, t)
					seen[key] = struct{}{}
				}
			}
		}
	}

	var vulns []model.Vulnerability
	for _, f := range allFindings {
		target := ""
		port := 0
		protocol := ""
		if f.Target != nil {
			target = f.Target.Host
			if f.Target.IP != "" {
				target = f.Target.IP
			}
			if f.Target.URL != "" {
				target = f.Target.URL
			}
			port = f.Target.Port
			protocol = f.Target.Protocol
		}
		severity := f.Severity
		if severity == "" {
			severity = "info"
		}
		vulns = append(vulns, model.Vulnerability{
			TaskID:       p.TaskID,
			Target:       target,
			Port:         port,
			Protocol:     protocol,
			Title:        f.Title,
			Description:  f.Description,
			Severity:     severity,
			Category:     f.Type,
			ModuleID:     f.ModuleID,
			DetectMethod: "active",
			Confidence:   f.Confidence,
			Evidence:     f.Evidence,
			Status:       model.VulnStatusOpen,
		})
	}

	result.Status = model.TaskStatusCompleted
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	scanRes := ScanResult{
		TaskID:          p.TaskID,
		Status:          result.Status,
		Progress:        100,
		Vulnerabilities: vulns,
	}
	raw, _ := json.Marshal(scanRes)
	result.Result = string(raw)

	slog.Info("scan done", "task_id", p.TaskID, "findings", len(allFindings))
	return result
}

func (e *Executor) Close() error { return nil }

func (e *Executor) resolveModules(profile string, config map[string]interface{}) []core.ScanModule {
	if profile == "" && config != nil {
		if p, ok := config["profile"].(string); ok {
			profile = p
		}
	}

	switch profile {
	case "quick":
		return []core.ScanModule{
			icmp.New(),
			portscan.New(),
			serviceprobe.New(),
			webcrawl.New(),
		}
	case "vuln":
		return []core.ScanModule{
			sqli.New(e.loader),
			xss.New(e.loader),
			weakpass.New(nil),
			ssrf.New("", e.loader),
		}
	case "recon":
		return []core.ScanModule{
			icmp.New(),
			portscan.New(),
			serviceprobe.New(),
			webcrawl.New(),
			dnsall.New(),
			favicon.New(),
			certcheck.New(),
			infoleak.New(),
		}
	default:
		return []core.ScanModule{
			icmp.New(),
			portscan.New(),
			serviceprobe.New(),
			webcrawl.New(),
			dnsall.New(),
			favicon.New(),
			certcheck.New(),
			infoleak.New(),
			dirscan.New(),
			sqli.New(e.loader),
			xss.New(e.loader),
			weakpass.New(nil),
			ssrf.New("", e.loader),
		}
	}
}
