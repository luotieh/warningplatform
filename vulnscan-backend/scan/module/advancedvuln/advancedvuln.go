package advancedvuln

import (
	"context"
	"log/slog"
	"sync"

	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/engine"
)

type AdvancedVulnScanner struct {
	clickjacking  *engine.ClickjackingScannerModule
	crlf          *engine.CRLFScannerModule
	hostHeader    *engine.HostHeaderScannerModule
	xssStored     *engine.XSSStoredScannerModule
	sensitiveData *engine.SensitiveDataScannerModule
	sessionFix    *engine.SessionFixationScannerModule
	httpSmuggling *engine.HTTPSmugglingScannerModule
	xmlrpc        *engine.XMLRPCScannerModule
	payloads      *payload.Loader
}

func New(loader *payload.Loader) *AdvancedVulnScanner {
	return &AdvancedVulnScanner{
		clickjacking:  engine.NewClickjackingScannerModule(nil),
		crlf:          engine.NewCRLFScannerModule(nil, loader),
		hostHeader:    engine.NewHostHeaderScannerModule(nil, loader),
		xssStored:     engine.NewXSSStoredScannerModule(nil),
		sensitiveData: engine.NewSensitiveDataScannerModule(nil),
		sessionFix:    engine.NewSessionFixationScannerModule(nil),
		httpSmuggling: engine.NewHTTPSmugglingScannerModule(nil),
		xmlrpc:        engine.NewXMLRPCScannerModule(nil),
		payloads:      loader,
	}
}

func (m *AdvancedVulnScanner) ID() string       { return "advanced_vuln" }
func (m *AdvancedVulnScanner) Name() string     { return "高级漏洞检测" }
func (m *AdvancedVulnScanner) Category() string { return "vuln" }

func (m *AdvancedVulnScanner) Params() []engine.ModuleParam {
	return nil
}

func (m *AdvancedVulnScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	result := &engine.ModuleResult{ModuleID: m.ID()}

	modules := []engine.ScanModule{
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
		go func(m engine.ScanModule) {
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
