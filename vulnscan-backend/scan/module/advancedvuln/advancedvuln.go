package advancedvuln

import (
	"context"
	"log/slog"
	"sync"

	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/vulnkit"
)

type AdvancedVulnScanner struct {
	clickjacking  *vulnkit.ClickjackingScannerModule
	crlf          *vulnkit.CRLFScannerModule
	hostHeader    *vulnkit.HostHeaderScannerModule
	xssStored     *vulnkit.XSSStoredScannerModule
	sensitiveData *vulnkit.SensitiveDataScannerModule
	sessionFix    *vulnkit.SessionFixationScannerModule
	httpSmuggling *vulnkit.HTTPSmugglingScannerModule
	xmlrpc        *vulnkit.XMLRPCScannerModule
	payloads      *payload.Loader
}

func New(loader *payload.Loader) *AdvancedVulnScanner {
	return &AdvancedVulnScanner{
		clickjacking:  vulnkit.NewClickjackingScannerModule(nil),
		crlf:          vulnkit.NewCRLFScannerModule(nil, loader),
		hostHeader:    vulnkit.NewHostHeaderScannerModule(nil, loader),
		xssStored:     vulnkit.NewXSSStoredScannerModule(nil),
		sensitiveData: vulnkit.NewSensitiveDataScannerModule(nil),
		sessionFix:    vulnkit.NewSessionFixationScannerModule(nil),
		httpSmuggling: vulnkit.NewHTTPSmugglingScannerModule(nil),
		xmlrpc:        vulnkit.NewXMLRPCScannerModule(nil),
		payloads:      loader,
	}
}

func (m *AdvancedVulnScanner) ID() string       { return "advanced_vuln" }
func (m *AdvancedVulnScanner) Name() string     { return "高级漏洞检测" }
func (m *AdvancedVulnScanner) Category() string { return "vuln" }

func (m *AdvancedVulnScanner) Params() []core.ModuleParam {
	return nil
}

func (m *AdvancedVulnScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	result := &core.ModuleResult{ModuleID: m.ID()}

	modules := []core.ScanModule{
		m.clickjacking,
		m.crlf,
		m.hostHeader,
		m.xssStored,
		m.sensitiveData,
		m.sessionFix,
		m.httpSmuggling,
		m.xmlrpc,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 4)

	for _, mod := range modules {
		wg.Add(1)
		sem <- struct{}{}
		go func(m core.ScanModule) {
			defer wg.Done()
			defer func() { <-sem }()

			modResult, err := m.Run(ctx, targets, config)
			if err != nil {
				slog.Error("[AdvancedVuln] 子模块执行失败", "module", m.ID(), "error", err)
				return
			}
			if modResult == nil {
				return
			}

			mu.Lock()
			result.Findings = append(result.Findings, modResult.Findings...)
			mu.Unlock()
		}(mod)
	}

	wg.Wait()

	slog.Info("[AdvancedVuln] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
	)

	return result, nil
}
