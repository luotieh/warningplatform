package scanrunner

import (
	"fmt"
	"sync"

	"gorm.io/gorm"

	"code.yt-security.com/public/scanengine/core"
	"code.yt-security.com/public/scanengine/dict"
	"code.yt-security.com/public/scanengine/module/advancedvuln"
	"code.yt-security.com/public/scanengine/module/apidisc"
	"code.yt-security.com/public/scanengine/module/apisec"
	"code.yt-security.com/public/scanengine/module/apisecurity"
	"code.yt-security.com/public/scanengine/module/bruteforce"
	"code.yt-security.com/public/scanengine/module/certcheck"
	"code.yt-security.com/public/scanengine/module/cmdi"
	"code.yt-security.com/public/scanengine/module/company"
	"code.yt-security.com/public/scanengine/module/cors"
	"code.yt-security.com/public/scanengine/module/credential"
	"code.yt-security.com/public/scanengine/module/dirscan"
	"code.yt-security.com/public/scanengine/module/dnsall"
	"code.yt-security.com/public/scanengine/module/dnsaxfr"
	"code.yt-security.com/public/scanengine/module/emailcollect"
	"code.yt-security.com/public/scanengine/module/favicon"
	"code.yt-security.com/public/scanengine/module/fingerprint"
	"code.yt-security.com/public/scanengine/module/fpenhance"
	"code.yt-security.com/public/scanengine/module/graphql"
	"code.yt-security.com/public/scanengine/module/hpp"
	"code.yt-security.com/public/scanengine/module/icmp"
	"code.yt-security.com/public/scanengine/module/idor"
	"code.yt-security.com/public/scanengine/module/infoleak"
	"code.yt-security.com/public/scanengine/module/injection"
	"code.yt-security.com/public/scanengine/module/ipattr"
	"code.yt-security.com/public/scanengine/module/jsanalyze"
	"code.yt-security.com/public/scanengine/module/jwtsec"
	"code.yt-security.com/public/scanengine/module/lfi"
	"code.yt-security.com/public/scanengine/module/nettopo"
	"code.yt-security.com/public/scanengine/module/nosqli"
	"code.yt-security.com/public/scanengine/module/openredirect"
	"code.yt-security.com/public/scanengine/module/portscan"
	"code.yt-security.com/public/scanengine/module/realip"
	"code.yt-security.com/public/scanengine/module/screenshot"
	"code.yt-security.com/public/scanengine/module/secheaders"
	"code.yt-security.com/public/scanengine/module/serviceprobe"
	"code.yt-security.com/public/scanengine/module/sqli"
	"code.yt-security.com/public/scanengine/module/ssrf"
	"code.yt-security.com/public/scanengine/module/ssti"
	"code.yt-security.com/public/scanengine/module/subdomain"
	"code.yt-security.com/public/scanengine/module/subtakeover"
	"code.yt-security.com/public/scanengine/module/synscan"
	"code.yt-security.com/public/scanengine/module/techdetect"
	"code.yt-security.com/public/scanengine/module/udpscan"
	"code.yt-security.com/public/scanengine/module/unauth"
	"code.yt-security.com/public/scanengine/module/wafdetect"
	"code.yt-security.com/public/scanengine/module/weakpass"
	"code.yt-security.com/public/scanengine/module/webcrawl"
	"code.yt-security.com/public/scanengine/module/webmisc"
	"code.yt-security.com/public/scanengine/module/wssec"
	"code.yt-security.com/public/scanengine/module/xss"
	"code.yt-security.com/public/scanengine/module/xxe"
	"code.yt-security.com/public/scanengine/payload"
	"code.yt-security.com/public/scanengine/rulestore"

	"vulnscan-backend/knowledge/nuclei"
)

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
	loader payload.Provider
	reg    *KnowledgeRegistry
}

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
	RegisterModule("port_scan", func(_ *ModuleDeps) core.ScanModule {
		if core.CanRawSYNScan() {
			return synscan.New()
		}
		return portscan.New()
	})
	RegisterModule("syn_scan", func(_ *ModuleDeps) core.ScanModule { return synscan.New() })
	RegisterModule("udp_scan", func(_ *ModuleDeps) core.ScanModule { return udpscan.New() })
	RegisterModule("service_probe", func(_ *ModuleDeps) core.ScanModule { return serviceprobe.New() })
	RegisterModule("subdomain_brute", func(d *ModuleDeps) core.ScanModule { return subdomain.New(d.Factory.ds) })
	RegisterModule("web_crawl", func(_ *ModuleDeps) core.ScanModule { return webcrawl.New() })
	RegisterModule("js_analyze", func(d *ModuleDeps) core.ScanModule { return jsanalyze.New(d.Factory.rs) })
	RegisterModule("waf_detect", func(d *ModuleDeps) core.ScanModule { return wafdetect.New(d.Factory.rs) })
	RegisterModule("tech_detect", func(d *ModuleDeps) core.ScanModule { return techdetect.New(d.Factory.rs) })
	RegisterModule("web_fingerprint", func(_ *ModuleDeps) core.ScanModule { return fingerprint.New() })
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
	RegisterModule("cors", func(_ *ModuleDeps) core.ScanModule { return cors.New() })
	RegisterModule("open_redirect", func(_ *ModuleDeps) core.ScanModule { return openredirect.New() })
	RegisterModule("hpp", func(_ *ModuleDeps) core.ScanModule { return hpp.New() })
	RegisterModule("sub_takeover", func(_ *ModuleDeps) core.ScanModule { return subtakeover.New() })
	RegisterModule("graphql", func(_ *ModuleDeps) core.ScanModule { return graphql.New() })
	RegisterModule("ws_sec", func(_ *ModuleDeps) core.ScanModule { return wssec.New() })
	RegisterModule("idor", func(_ *ModuleDeps) core.ScanModule { return idor.New() })
	RegisterModule("sec_headers", func(_ *ModuleDeps) core.ScanModule { return secheaders.New() })
	RegisterModule("dns_axfr", func(_ *ModuleDeps) core.ScanModule { return dnsaxfr.New() })

	RegisterModule("injection", func(d *ModuleDeps) core.ScanModule { return injection.New(d.Factory.loader) })
	RegisterModule("api_security", func(_ *ModuleDeps) core.ScanModule { return apisecurity.New() })
	RegisterModule("credential", func(d *ModuleDeps) core.ScanModule { return credential.New(d.Factory.ds) })
	RegisterModule("web_misc", func(_ *ModuleDeps) core.ScanModule { return webmisc.New() })

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
