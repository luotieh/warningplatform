package scheduler

import "vulnscan-backend/scan/engine"

type stageGroup struct {
	name    string
	modules []engine.ScanModule
}

var fastReconModules = map[string]struct{}{
	"tech_detect":  {},
	"waf_detect":   {},
	"favicon_scan": {},
	"cert_check":   {},
	"dns_all":      {},
	"ip_attr":      {},
	"real_ip":      {},
}

func BuildStages(modules []engine.ScanModule) []stageGroup {
	categoryOrder := []string{"discover", "host", "probe", "recon", "vuln"}
	grouped := make(map[string][]engine.ScanModule)

	for _, m := range modules {
		cat := m.Category()
		grouped[cat] = append(grouped[cat], m)
	}

	var stages []stageGroup
	for _, cat := range categoryOrder {
		mods, ok := grouped[cat]
		if !ok || len(mods) == 0 {
			continue
		}

		if cat == "recon" && len(mods) > 4 {
			var fast, deep []engine.ScanModule
			for _, m := range mods {
				if _, ok := fastReconModules[m.ID()]; ok {
					fast = append(fast, m)
				} else {
					deep = append(deep, m)
				}
			}
			if len(fast) > 0 {
				stages = append(stages, stageGroup{name: "recon-fast", modules: fast})
			}
			if len(deep) > 0 {
				stages = append(stages, stageGroup{name: "recon-deep", modules: deep})
			}
		} else {
			stages = append(stages, stageGroup{name: cat, modules: mods})
		}
	}

	for cat, mods := range grouped {
		found := false
		for _, c := range categoryOrder {
			if c == cat {
				found = true
				break
			}
		}
		if !found {
			stages = append(stages, stageGroup{name: cat, modules: mods})
		}
	}

	return stages
}
