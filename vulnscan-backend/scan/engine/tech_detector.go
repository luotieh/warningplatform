package engine

import (
	"fmt"
	"log/slog"
	"strings"
)

type TechEvidence struct {
	Source     string    `json:"source"`
	TechStack  TechStack `json:"tech_stack"`
	Confidence float64   `json:"confidence"`
	Detail     string    `json:"detail"`
}

type AdvancedTechProfile struct {
	Stack            TechStack      `json:"stack"`
	Confidence       float64        `json:"confidence"`
	Framework        string         `json:"framework"`
	Server           string         `json:"server"`
	Version          string         `json:"version"`
	Evidence         []TechEvidence `json:"evidence"`
	RecommendModules []string       `json:"recommend_modules"`
	SkipModules      []string       `json:"skip_modules"`
	HighPriority     []string       `json:"high_priority"`
}

type AdvancedTechDetector struct {
	httpFingerprints map[string]TechStack
	portServiceMap   map[int]TechStack
}

func NewAdvancedTechDetector() *AdvancedTechDetector {
	return &AdvancedTechDetector{
		httpFingerprints: buildHTTPFingerprintMap(),
		portServiceMap:   buildPortTechMap(),
	}
}

func (d *AdvancedTechDetector) Detect(targets []*Target, findings []*Finding) *AdvancedTechProfile {
	scores := make(map[TechStack]float64)
	var evidence []TechEvidence

	for _, t := range targets {
		if t.Fingerprints != nil {
			for _, fp := range t.Fingerprints {
				tech := d.mapFingerprintToTech(fp)
				if tech != TechGeneric {
					conf := float64(fp.Confidence) / 100.0
					scores[tech] += conf * 2.0
					evidence = append(evidence, TechEvidence{
						Source:     "http_fingerprint",
						TechStack:  tech,
						Confidence: conf * 2.0,
						Detail:     fp.Product,
					})
				}
			}
		}

		if t.Port > 0 {
			if tech, ok := d.portServiceMap[t.Port]; ok {
				scores[tech] += 0.5
				evidence = append(evidence, TechEvidence{
					Source:     "port_service",
					TechStack:  tech,
					Confidence: 0.2,
					Detail:     fmt.Sprintf("port %d", t.Port),
				})
			}
		}
	}

	for _, f := range findings {
		if f.Type == "vulnerability" || f.Type == "fingerprint" {
			tech := d.findingToTechStack(f)
			if tech != TechGeneric {
				scores[tech] += 3.0
				evidence = append(evidence, TechEvidence{
					Source:     "vuln_finding",
					TechStack:  tech,
					Confidence: 0.4,
					Detail:     f.Title,
				})
			}
		}
	}

	bestStack, confidence := normalizeAndSelect(scores)

	profile := &AdvancedTechProfile{
		Stack:      bestStack,
		Confidence: confidence,
		Evidence:   evidence,
	}

	d.enrichProfile(profile, targets, findings)

	return profile
}

func (d *AdvancedTechDetector) mapFingerprintToTech(fp Fingerprint) TechStack {
	product := strings.ToLower(fp.Product)

	if containsAnyTech(product, "php", "wordpress", "drupal", "joomla", "laravel", "codeigniter", "symfony") {
		return TechPHP
	}
	if containsAnyTech(product, "java", "tomcat", "jetty", "spring", "jboss", "weblogic", "jenkins") {
		return TechJava
	}
	if containsAnyTech(product, "python", "django", "flask", "fastapi", "tornado") {
		return TechPython
	}
	if containsAnyTech(product, "node.js", "nodejs", "express", "koa", "next.js", "nuxt.js") {
		return TechNode
	}
	if containsAnyTech(product, "asp.net", "iis", ".net", "mvc") {
		return TechASPNET
	}
	if containsAnyTech(product, "ruby", "rails", "sinatra") {
		return TechRuby
	}
	if containsAnyTech(product, "nginx") {
		return TechGo
	}
	if containsAnyTech(product, "apache") {
		return TechGeneric
	}
	if containsAnyTech(product, "mysql") {
		return TechJava
	}
	if containsAnyTech(product, "postgresql") {
		return TechJava
	}
	if containsAnyTech(product, "redis") {
		return TechGeneric
	}
	if containsAnyTech(product, "mongodb") {
		return TechNode
	}

	return TechGeneric
}

func (d *AdvancedTechDetector) findingToTechStack(f *Finding) TechStack {
	title := strings.ToLower(f.Title + " " + f.Description)
	data := ""
	if f.Data != nil {
		for _, v := range f.Data {
			data += " " + strings.ToLower(v)
		}
	}
	combined := title + data

	if containsAnyTech(combined, "php", "wordpress", "drupal", "joomla", "laravel", "codeigniter", "symfony", "x-powered-by: php") {
		return TechPHP
	}
	if containsAnyTech(combined, "java", "spring", "tomcat", "jetty", "jboss", "weblogic", "struts", "log4j") {
		return TechJava
	}
	if containsAnyTech(combined, "python", "django", "flask", "fastapi", "tornado", "wsgi") {
		return TechPython
	}
	if containsAnyTech(combined, "node.js", "nodejs", "express", "koa", "npm") {
		return TechNode
	}
	if containsAnyTech(combined, "asp.net", "iis", ".net", "c#", "mvc") {
		return TechASPNET
	}
	if containsAnyTech(combined, "ruby", "rails", "sinatra", "rack") {
		return TechRuby
	}

	return TechGeneric
}

func (d *AdvancedTechDetector) enrichProfile(profile *AdvancedTechProfile, targets []*Target, findings []*Finding) {
	switch profile.Stack {
	case TechPHP:
		profile.RecommendModules = []string{"php_rce", "php_sqli", "php_upload", "php_include"}
		profile.SkipModules = []string{"java_deserialize", "spring_rce", "struts_rce"}
		profile.HighPriority = []string{"wordpress_rce", "laravel_rce"}
	case TechJava:
		profile.RecommendModules = []string{"java_deserialize", "spring_rce", "struts_rce", "log4j_rce"}
		profile.SkipModules = []string{"php_rce", "php_sqli", "wordpress_rce"}
		profile.HighPriority = []string{"log4j_rce", "spring_rce"}
	case TechPython:
		profile.RecommendModules = []string{"python_rce", "python_sqli", "flask_rce", "django_rce"}
		profile.SkipModules = []string{"java_deserialize", "php_rce", "asp_rce"}
		profile.HighPriority = []string{"flask_rce", "django_rce"}
	case TechNode:
		profile.RecommendModules = []string{"nodejs_rce", "nodejs_sqli", "express_rce"}
		profile.SkipModules = []string{"java_deserialize", "php_rce", "asp_rce"}
		profile.HighPriority = []string{"nodejs_rce"}
	case TechASPNET:
		profile.RecommendModules = []string{"asp_rce", "asp_sqli", "iis_rce"}
		profile.SkipModules = []string{"php_rce", "java_deserialize", "python_rce"}
		profile.HighPriority = []string{"asp_rce"}
	default:
		profile.RecommendModules = []string{"common_rce", "common_sqli", "common_xss"}
		profile.SkipModules = []string{}
		profile.HighPriority = []string{"common_rce"}
	}

	for _, t := range targets {
		if t.Product != "" {
			profile.Framework = t.Product
		}
		if t.Version != "" {
			profile.Version = t.Version
		}
		if t.Service != "" {
			profile.Server = t.Service
		}
	}
}

func normalizeAndSelect(scores map[TechStack]float64) (TechStack, float64) {
	if len(scores) == 0 {
		return TechGeneric, 0.0
	}

	var maxScore float64
	var bestStack TechStack
	var totalScore float64

	for tech, score := range scores {
		totalScore += score
		if score > maxScore {
			maxScore = score
			bestStack = tech
		}
	}

	confidence := maxScore / totalScore
	if confidence > 1.0 {
		confidence = 1.0
	}

	return bestStack, confidence
}

func containsAnyTech(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func buildHTTPFingerprintMap() map[string]TechStack {
	return map[string]TechStack{
		"php":       TechPHP,
		"wordpress": TechPHP,
		"drupal":    TechPHP,
		"joomla":    TechPHP,
		"laravel":   TechPHP,
		"java":      TechJava,
		"tomcat":    TechJava,
		"spring":    TechJava,
		"python":    TechPython,
		"django":    TechPython,
		"flask":     TechPython,
		"node.js":   TechNode,
		"express":   TechNode,
		"asp.net":   TechASPNET,
		"iis":       TechASPNET,
		"nginx":     TechGo,
		"apache":    TechGeneric,
		"mysql":     TechJava,
		"redis":     TechGeneric,
		"mongodb":   TechNode,
	}
}

func buildPortTechMap() map[int]TechStack {
	return map[int]TechStack{
		80:    TechGo,
		443:   TechGo,
		8080:  TechJava,
		8443:  TechJava,
		3000:  TechNode,
		5000:  TechPython,
		3306:  TechJava,
		5432:  TechJava,
		6379:  TechGeneric,
		27017: TechNode,
		9200:  TechJava,
	}
}

func init() {
	slog.Debug("[AdvancedTechDetector] 高级技术栈检测器就绪")
}
