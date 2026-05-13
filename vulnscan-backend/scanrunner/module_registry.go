package scanrunner

import (
	"time"

	"gorm.io/gorm"

	"vulnscan-backend/dict"
	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/model"
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

var profileTimeouts = map[string]time.Duration{
	"quick":     1 * time.Minute,
	"recon":     3 * time.Minute,
	"vuln":      3 * time.Minute,
	"vuln-full": 5 * time.Minute,
	"full":      2 * time.Minute,
}

func ResolveProfileTimeout(task model.ScanTask) time.Duration {
	profile := resolveProfile(task)
	if t, ok := profileTimeouts[profile]; ok {
		return t
	}
	return defaultModuleTimeout
}

func resolveProfile(task model.ScanTask) string {
	if task.Config != nil {
		if p, ok := task.Config["profile"].(string); ok && p != "" {
			return p
		}
	}
	if task.Type != "" {
		return task.Type
	}
	return "full"
}

func ResolveModules(db *gorm.DB, task model.ScanTask) []core.ScanModule {
	profile := resolveProfile(task)
	rs := rulestore.NewWithoutDB()
	ds := dict.NewStore(nil)
	pl := payload.NewLoader(db)
	_ = pl.LoadAll()

	var modules []core.ScanModule

	switch profile {
	case "quick":
		modules = append(modules,
			icmp.New(),
			portscan.New(),
			serviceprobe.NewWithDB(db),
			webcrawl.New(),
		)
	case "full":
		modules = allModules(db, rs, ds, pl)
	case "recon":
		modules = append(modules,
			icmp.New(),
			portscan.New(),
			synscan.New(),
			udpscan.New(),
			serviceprobe.NewWithDB(db),
			subdomain.New(ds),
			webcrawl.New(),
			jsanalyze.New(rs),
			wafdetect.New(rs),
			techdetect.New(rs),
			fingerprint.NewWithDB(db),
			dnsall.New(),
			favicon.New(),
			certcheck.New(),
			apidisc.New(),
			infoleak.New(),
			ipattr.New(),
			realip.New(),
			company.New(),
			emailcollect.New(),
			screenshot.New(),
		)
	case "vuln":
		modules = append(modules,
			sqli.New(pl),
			xss.New(pl),
			weakpass.New(),
			bruteforce.New(ds),
			ssrf.New("", pl),
			cmdi.New(pl),
			lfi.New(pl),
			ssti.New(pl),
			xxe.New(pl),
			nosqli.New(pl),
			jwtsec.New(),
			advancedvuln.New(pl),
			unauth.New(),
		)
	case "vuln-full":
		modules = append(modules,
			sqli.New(pl),
			xss.New(pl),
			weakpass.New(),
			bruteforce.New(ds),
			ssrf.New("", pl),
			cmdi.New(pl),
			lfi.New(pl),
			ssti.New(pl),
			xxe.New(pl),
			nosqli.New(pl),
			jwtsec.New(),
			apisec.New(),
			advancedvuln.New(pl),
			unauth.New(),
		)
	default:
		modules = allModules(db, rs, ds, pl)
	}

	if enabledModules, ok := task.Config["modules"]; ok {
		if moduleList, ok := enabledModules.([]interface{}); ok && len(moduleList) > 0 {
			enabledSet := make(map[string]struct{})
			for _, m := range moduleList {
				if ms, ok := m.(string); ok {
					enabledSet[ms] = struct{}{}
				}
			}
			var filtered []core.ScanModule
			for _, m := range modules {
				if _, ok := enabledSet[m.ID()]; ok {
					filtered = append(filtered, m)
				}
			}
			if len(filtered) > 0 {
				modules = filtered
			}
		}
	}

	return modules
}

func allModules(db *gorm.DB, rs *rulestore.Store, ds *dict.Store, pl *payload.Loader) []core.ScanModule {
	return []core.ScanModule{
		icmp.New(),
		portscan.New(),
		synscan.New(),
		udpscan.New(),
		serviceprobe.NewWithDB(db),
		subdomain.New(ds),
		webcrawl.New(),
		jsanalyze.New(rs),
		wafdetect.New(rs),
		techdetect.New(rs),
		fingerprint.NewWithDB(db),
		dnsall.New(),
		favicon.New(),
		certcheck.New(),
		apidisc.New(),
		infoleak.New(),
		ipattr.New(),
		realip.New(),
		company.New(),
		emailcollect.New(),
		screenshot.New(),
		dirscan.New(),
		sqli.New(pl),
		xss.New(pl),
		weakpass.New(),
		bruteforce.New(ds),
		ssrf.New("", pl),
		cmdi.New(pl),
		lfi.New(pl),
		ssti.New(pl),
		xxe.New(pl),
		nosqli.New(pl),
		jwtsec.New(),
		apisec.New(),
		fpenhance.New(),
		nettopo.New(),
		nuclei.NewModule(db),
		advancedvuln.New(pl),
		unauth.New(),
	}
}
