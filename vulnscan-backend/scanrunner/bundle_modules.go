package scanrunner

import (
	"code.yt-security.com/public/scanengine/core"
	"code.yt-security.com/public/scanengine/module/advancedvuln"
	"code.yt-security.com/public/scanengine/module/apisecurity"
	"code.yt-security.com/public/scanengine/module/bundle"
	"code.yt-security.com/public/scanengine/module/certcheck"
	"code.yt-security.com/public/scanengine/module/cmdi"
	"code.yt-security.com/public/scanengine/module/company"
	"code.yt-security.com/public/scanengine/module/credential"
	"code.yt-security.com/public/scanengine/module/dnsall"
	"code.yt-security.com/public/scanengine/module/dnsaxfr"
	"code.yt-security.com/public/scanengine/module/emailcollect"
	"code.yt-security.com/public/scanengine/module/fingerprint"
	"code.yt-security.com/public/scanengine/module/icmp"
	"code.yt-security.com/public/scanengine/module/infoleak"
	"code.yt-security.com/public/scanengine/module/injection"
	"code.yt-security.com/public/scanengine/module/ipattr"
	"code.yt-security.com/public/scanengine/module/lfi"
	"code.yt-security.com/public/scanengine/module/nettopo"
	"code.yt-security.com/public/scanengine/module/portscan"
	"code.yt-security.com/public/scanengine/module/realip"
	"code.yt-security.com/public/scanengine/module/screenshot"
	"code.yt-security.com/public/scanengine/module/sqli"
	"code.yt-security.com/public/scanengine/module/ssrf"
	"code.yt-security.com/public/scanengine/module/subdomain"
	"code.yt-security.com/public/scanengine/module/subtakeover"
	"code.yt-security.com/public/scanengine/module/synscan"
	"code.yt-security.com/public/scanengine/module/udpscan"
	"code.yt-security.com/public/scanengine/module/wafdetect"
	"code.yt-security.com/public/scanengine/module/webcrawl"
	"code.yt-security.com/public/scanengine/module/webmisc"
	"code.yt-security.com/public/scanengine/module/xss"
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
		return bundle.New("web_recon", "Web 信息收集", "recon", 8, []core.ScanModule{
			subdomain.New(d.Factory.ds),
			dnsall.New(),
			dnsaxfr.New(),
			webcrawl.New(),
			wafdetect.New(d.Factory.rs),
			fingerprint.New(),
			ipattr.New(),
			realip.New(),
			company.New(),
			emailcollect.New(),
			certcheck.New(),
			infoleak.New(),
			screenshot.New(),
			subtakeover.New(),
		})
	})

	RegisterModule("asset_enrich", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("asset_enrich", "资产富化", "recon", 3, []core.ScanModule{
			dnsall.New(),
			ipattr.New(),
		})
	})

	RegisterModule("web_vuln_scan", func(d *ModuleDeps) core.ScanModule {
		loader := d.Factory.loader
		return bundle.New("web_vuln_scan", "Web 漏洞检测", "vuln", 10, []core.ScanModule{
			sqli.New(loader),
			xss.New(loader),
			cmdi.New(loader),
			ssrf.New("", loader),
			lfi.New(loader),
			injection.New(loader),
			apisecurity.New(),
			webmisc.New(),
			advancedvuln.New(loader),
		})
	})

	RegisterModule("credential_audit", func(d *ModuleDeps) core.ScanModule {
		return credential.New(d.Factory.ds)
	})

	RegisterModule("infra_extra", func(d *ModuleDeps) core.ScanModule {
		return bundle.New("infra_extra", "网络拓扑", "recon", 1, []core.ScanModule{
			nettopo.New(),
		})
	})
}

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
		"infra_extra",
	}
}
