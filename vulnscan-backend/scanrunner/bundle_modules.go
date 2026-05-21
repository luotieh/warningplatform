package scanrunner

import (
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/module/advancedvuln"
	"vulnscan-backend/scan/module/apidisc"
	"vulnscan-backend/scan/module/apisec"
	"vulnscan-backend/scan/module/bruteforce"
	"vulnscan-backend/scan/module/bundle"
	"vulnscan-backend/scan/module/certcheck"
	"vulnscan-backend/scan/module/cmdi"
	"vulnscan-backend/scan/module/company"
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
)

func registerBundleModules() {
	RegisterModule("host_discover", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("host_discover", "主机发现", "discover", 4, []core.ScanModule{
			icmp.New(),
			portscan.New(),
			synscan.New(),
			udpscan.New(),
		})
	})
	RegisterModule("web_recon", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("web_recon", "Web 信息收集", "recon", 6, []core.ScanModule{
			subdomain.New(d.Factory.ds),
			webcrawl.New(),
			techdetect.New(d.Factory.rs),
			wafdetect.New(d.Factory.rs),
			favicon.New(),
			certcheck.New(),
			dnsall.New(),
			ipattr.New(),
			realip.New(),
			jsanalyze.New(d.Factory.rs),
			fingerprint.NewWithDB(d.Factory.db),
			apidisc.New(),
			infoleak.New(),
			company.New(),
			emailcollect.New(),
			screenshot.New(),
			fpenhance.New(),
		})
	})
	RegisterModule("asset_enrich", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("asset_enrich", "资产富化", "recon", 3, []core.ScanModule{
			dnsall.New(),
			ipattr.New(),
			certcheck.New(),
		})
	})
	RegisterModule("web_vuln_scan", func(d *ModuleDeps) core.ScanModule {
		loader := d.Factory.loader
		return bundle.New("web_vuln_scan", "Web 漏洞检测", "vuln", 6, []core.ScanModule{
			sqli.New(loader),
			xss.New(loader),
			ssrf.New("", loader),
			cmdi.New(loader),
			lfi.New(loader),
			ssti.New(loader),
			xxe.New(loader),
			nosqli.New(loader),
			jwtsec.New(),
			apisec.New(),
			advancedvuln.New(loader),
		})
	})
	RegisterModule("credential_audit", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("credential_audit", "凭据安全", "vuln", 3, []core.ScanModule{
			weakpass.New(d.Factory.ds),
			bruteforce.New(d.Factory.ds),
			unauth.New(),
		})
	})
	RegisterModule("infra_extra", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("infra_extra", "网络拓扑", "recon", 1, []core.ScanModule{
			nettopo.New(),
		})
	})
}

// PrimaryModuleIDs 模板编辑器展示的模块（组合模块 + 少量独立模块）。
func PrimaryModuleIDs() []string {
	return []string{
		"host_discover",
		"service_probe",
		"web_recon",
		"asset_enrich",
		"web_crawl",
		"web_vuln_scan",
		"credential_audit",
		"nuclei-poc",
		"dir_scan",
		"infra_extra",
	}
}
