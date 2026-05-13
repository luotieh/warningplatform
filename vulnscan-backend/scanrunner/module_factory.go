package scanrunner

import (
	"fmt"

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

type ModuleFactory struct {
	db     *gorm.DB
	rs     *rulestore.Store
	ds     *dict.Store
	loader *payload.Loader
}

func NewModuleFactory(db *gorm.DB) *ModuleFactory {
	rs := rulestore.NewWithoutDB()
	ds := dict.NewStore(nil)
	pl := payload.NewLoader(db)
	_ = pl.LoadAll()
	return &ModuleFactory{db: db, rs: rs, ds: ds, loader: pl}
}

func (f *ModuleFactory) Build(id string) core.ScanModule {
	switch id {
	case "icmp_ping":
		return icmp.New()
	case "port_scan":
		return portscan.New()
	case "syn_scan":
		return synscan.New()
	case "udp_scan":
		return udpscan.New()
	case "service_probe":
		return serviceprobe.NewWithDB(f.db)
	case "subdomain_brute":
		return subdomain.New(f.ds)
	case "web_crawl":
		return webcrawl.New()
	case "js_analyze":
		return jsanalyze.New(f.rs)
	case "waf_detect":
		return wafdetect.New(f.rs)
	case "tech_detect":
		return techdetect.New(f.rs)
	case "web_fingerprint":
		return fingerprint.NewWithDB(f.db)
	case "dns_all":
		return dnsall.New()
	case "favicon":
		return favicon.New()
	case "cert_check":
		return certcheck.New()
	case "api_disc":
		return apidisc.New()
	case "info_leak":
		return infoleak.New()
	case "ip_attr":
		return ipattr.New()
	case "real_ip":
		return realip.New()
	case "company_recon":
		return company.New()
	case "email_collect":
		return emailcollect.New()
	case "screenshot":
		return screenshot.New()
	case "dir_scan":
		return dirscan.New()
	case "sqli":
		return sqli.New(f.loader)
	case "xss":
		return xss.New(f.loader)
	case "weak_pass":
		return weakpass.New()
	case "brute_force":
		return bruteforce.New(f.ds)
	case "ssrf":
		return ssrf.New("", f.loader)
	case "cmdi":
		return cmdi.New(f.loader)
	case "lfi":
		return lfi.New(f.loader)
	case "ssti":
		return ssti.New(f.loader)
	case "xxe":
		return xxe.New(f.loader)
	case "nosqli":
		return nosqli.New(f.loader)
	case "jwt_sec":
		return jwtsec.New()
	case "apisec":
		return apisec.New()
	case "fpenhance":
		return fpenhance.New()
	case "nettopo":
		return nettopo.New()
	case "nuclei-poc":
		return nuclei.NewModule(f.db)
	case "advanced_vuln":
		return advancedvuln.New(f.loader)
	case "unauth":
		return unauth.New()
	default:
		return nil
	}
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
	return []string{
		"icmp_ping", "port_scan", "syn_scan", "udp_scan",
		"service_probe", "subdomain_brute", "web_crawl",
		"js_analyze", "waf_detect", "tech_detect", "web_fingerprint",
		"dns_all", "favicon", "cert_check", "api_disc", "info_leak",
		"ip_attr", "real_ip", "company_recon", "email_collect", "screenshot",
		"dir_scan", "sqli", "xss", "weak_pass", "brute_force",
		"ssrf", "cmdi", "lfi", "ssti", "xxe", "nosqli",
		"jwt_sec", "apisec", "fpenhance", "nettopo", "nuclei-poc",
		"advanced_vuln", "unauth",
	}
}
