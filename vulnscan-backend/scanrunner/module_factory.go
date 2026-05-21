package scanrunner

import (
	"fmt"
	"sync"

	"gorm.io/gorm"

	"vulnscan-backend/dict"
	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/module/advancedvuln"
	"vulnscan-backend/scan/module/apidisc"
	"vulnscan-backend/scan/module/apisec"
	"vulnscan-backend/scan/module/bruteforce"
	"vulnscan-backend/scan/module/certcheck"
	"vulnscan-backend/scan/module/cmdi"
	"vulnscan-backend/scan/module/company"
	"vulnscan-backend/scan/module/dirscan"
	"vulnscan-backend/scan/module/dnsall"
	"vulnscan-backend/scan/module/emailcollect"
	"vulnscan-backend/scan/module/favicon"
	"vulnscan-backend/scan/module/fingerprint"
	"vulnscan-backend/scan/module/fpenhance"
	"vulnscan-backend/scan/module/icmp"
	"vulnscan-backend/scan/module/infoleak"
	"vulnscan-backend/scan/module/ipattr"
	"vulnscan-backend/scan/module/jsanalyze"
	"vulnscan-backend/scan/module/jwtsec"
	"vulnscan-backend/scan/module/lfi"
	"vulnscan-backend/scan/module/nettopo"
	"vulnscan-backend/scan/module/nosqli"
	"vulnscan-backend/scan/module/portscan"
	"vulnscan-backend/scan/module/realip"
	"vulnscan-backend/scan/module/screenshot"
	"vulnscan-backend/scan/module/serviceprobe"
	"vulnscan-backend/scan/module/sqli"
	"vulnscan-backend/scan/module/ssrf"
	"vulnscan-backend/scan/module/ssti"
	"vulnscan-backend/scan/module/subdomain"
	"vulnscan-backend/scan/module/synscan"
	"vulnscan-backend/scan/module/techdetect"
	"vulnscan-backend/scan/module/udpscan"
	"vulnscan-backend/scan/module/unauth"
	"vulnscan-backend/scan/module/wafdetect"
	"vulnscan-backend/scan/module/weakpass"
	"vulnscan-backend/scan/module/webcrawl"
	"vulnscan-backend/scan/module/xss"
	"vulnscan-backend/scan/module/xxe"
	"vulnscan-backend/scan/rulestore"
)

// PLACEHOLDER_FACTORY_BODY

var registerModulesOnce sync.Once

func ensureModulesRegistered() {
	registerModulesOnce.Do(func() {
		(&ModuleFactory{}).registerAll()
	})
}

type ModuleFactory struct {
	db     *gorm.DB
	rs     *rulestore.Store
	ds     *dict.Store
	loader *payload.Loader
	reg    *KnowledgeRegistry
}

// NewModuleFactory 优先使用 DefaultKnowledgeRegistry，否则临时创建（测试用）。
func NewModuleFactory(db *gorm.DB) *ModuleFactory {
	ensureModulesRegistered()
	if reg := DefaultKnowledgeRegistry(); reg != nil {
		return reg.NewModuleFactory()
	}
	reg := NewKnowledgeRegistry(db)
	SetDefaultKnowledgeRegistry(reg)
	return reg.NewModuleFactory()
}

func (f *ModuleFactory) registerAll() {
	RegisterModule("icmp_ping", func(_ *ModuleDeps) core.ScanModule { return icmp.New() })
	RegisterModule("port_scan", func(_ *ModuleDeps) core.ScanModule { return portscan.New() })
	RegisterModule("syn_scan", func(_ *ModuleDeps) core.ScanModule { return synscan.New() })
	RegisterModule("udp_scan", func(_ *ModuleDeps) core.ScanModule { return udpscan.New() })
	RegisterModule("service_probe", func(d *ModuleDeps) core.ScanModule { return serviceprobe.NewWithDB(d.Factory.db) })
	RegisterModule("subdomain_brute", func(d *ModuleDeps) core.ScanModule { return subdomain.New(d.Factory.ds) })
	RegisterModule("web_crawl", func(_ *ModuleDeps) core.ScanModule { return webcrawl.New() })
	RegisterModule("js_analyze", func(d *ModuleDeps) core.ScanModule { return jsanalyze.New(d.Factory.rs) })
	RegisterModule("waf_detect", func(d *ModuleDeps) core.ScanModule { return wafdetect.New(d.Factory.rs) })
	RegisterModule("tech_detect", func(d *ModuleDeps) core.ScanModule { return techdetect.New(d.Factory.rs) })
	RegisterModule("web_fingerprint", func(d *ModuleDeps) core.ScanModule { return fingerprint.NewWithDB(d.Factory.db) })
	RegisterModule("dns_all", func(_ *ModuleDeps) core.ScanModule { return dnsall.New() })
	RegisterModule("favicon", func(_ *ModuleDeps) core.ScanModule { return favicon.New() })
	RegisterModule("cert_check", func(_ *ModuleDeps) core.ScanModule { return certcheck.New() })
	RegisterModule("api_disc", func(_ *ModuleDeps) core.ScanModule { return apidisc.New() })
	RegisterModule("info_leak", func(_ *ModuleDeps) core.ScanModule { return infoleak.New() })
	RegisterModule("ip_attr", func(_ *ModuleDeps) core.ScanModule { return ipattr.New() })
	RegisterModule("real_ip", func(_ *ModuleDeps) core.ScanModule { return realip.New() })
	RegisterModule("company_recon", func(_ *ModuleDeps) core.ScanModule { return company.New() })
	RegisterModule("email_collect", func(_ *ModuleDeps) core.ScanModule { return emailcollect.New() })
	RegisterModule("screenshot", func(_ *ModuleDeps) core.ScanModule { return screenshot.New() })
	RegisterModule("dir_scan", func(d *ModuleDeps) core.ScanModule { return dirscan.NewWithDict(d.Factory.ds) })
	RegisterModule("sqli", func(d *ModuleDeps) core.ScanModule { return sqli.New(d.Factory.loader) })
	RegisterModule("xss", func(d *ModuleDeps) core.ScanModule { return xss.New(d.Factory.loader) })
	RegisterModule("weak_pass", func(d *ModuleDeps) core.ScanModule { return weakpass.New(d.Factory.ds) })
	RegisterModule("brute_force", func(d *ModuleDeps) core.ScanModule { return bruteforce.New(d.Factory.ds) })
	RegisterModule("ssrf", func(d *ModuleDeps) core.ScanModule { return ssrf.New("", d.Factory.loader) })
	RegisterModule("cmdi", func(d *ModuleDeps) core.ScanModule { return cmdi.New(d.Factory.loader) })
	RegisterModule("lfi", func(d *ModuleDeps) core.ScanModule { return lfi.New(d.Factory.loader) })
	RegisterModule("ssti", func(d *ModuleDeps) core.ScanModule { return ssti.New(d.Factory.loader) })
	RegisterModule("xxe", func(d *ModuleDeps) core.ScanModule { return xxe.New(d.Factory.loader) })
	RegisterModule("nosqli", func(d *ModuleDeps) core.ScanModule { return nosqli.New(d.Factory.loader) })
	RegisterModule("jwt_sec", func(_ *ModuleDeps) core.ScanModule { return jwtsec.New() })
	RegisterModule("apisec", func(_ *ModuleDeps) core.ScanModule { return apisec.New() })
	RegisterModule("fpenhance", func(_ *ModuleDeps) core.ScanModule { return fpenhance.New() })
	RegisterModule("nettopo", func(_ *ModuleDeps) core.ScanModule { return nettopo.New() })
	RegisterModule("nuclei-poc", func(d *ModuleDeps) core.ScanModule {
		if d.Factory.reg != nil && d.Factory.reg.Poc != nil {
			return nuclei.NewModuleWithStore(d.Factory.db, d.Factory.reg.Poc)
		}
		return nuclei.NewModule(d.Factory.db)
	})
	RegisterModule("advanced_vuln", func(d *ModuleDeps) core.ScanModule { return advancedvuln.New(d.Factory.loader) })
	RegisterModule("unauth", func(_ *ModuleDeps) core.ScanModule { return unauth.New() })
	registerBundleModules()
}

func (f *ModuleFactory) Build(id string) core.ScanModule {
	if builder, ok := GetModuleBuilder(id); ok {
		return builder(&ModuleDeps{Factory: f})
	}
	return nil
}

func (f *ModuleFactory) BuildMany(ids []string) ([]core.ScanModule, error) {
	modules := make([]core.ScanModule, 0, len(ids))
	for _, id := range ids {
		m := f.Build(id)
		if m == nil {
			return nil, fmt.Errorf("未知模块: %s", id)
		}
		modules = append(modules, m)
	}
	return modules, nil
}

func (f *ModuleFactory) AllIDs() []string {
	return RegisteredModuleIDs()
}
