package engine

import "strings"

type WAFInfo struct {
	Name     string
	Category string
}

type ScanContext struct {
	WAFs     []WAFInfo
	Products []string
}

func BuildScanContext(config map[string]interface{}) *ScanContext {
	sc := &ScanContext{}

	sc.Products = GetConfigStringSlice(config, "detected_products")

	if wafs := GetConfigStringSlice(config, "detected_wafs"); len(wafs) > 0 {
		for _, w := range wafs {
			sc.WAFs = append(sc.WAFs, WAFInfo{Name: w})
		}
	}

	return sc
}

func (sc *ScanContext) HasWAF() bool {
	return len(sc.WAFs) > 0
}

func (sc *ScanContext) WAFNames() []string {
	var names []string
	for _, w := range sc.WAFs {
		names = append(names, w.Name)
	}
	return names
}

func (sc *ScanContext) HasProduct(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range sc.Products {
		if strings.Contains(strings.ToLower(p), lower) {
			return true
		}
	}
	return false
}

func (sc *ScanContext) HasAnyProduct(names ...string) bool {
	for _, n := range names {
		if sc.HasProduct(n) {
			return true
		}
	}
	return false
}

func (sc *ScanContext) DetectedOS() string {
	if sc.HasAnyProduct("windows", "iis", "asp.net", "mssql") {
		return "windows"
	}
	if sc.HasAnyProduct("linux", "ubuntu", "debian", "centos", "redhat", "alpine") {
		return "linux"
	}
	return ""
}

func (sc *ScanContext) DetectedDBType() string {
	if sc.HasAnyProduct("mysql", "mariadb") {
		return "mysql"
	}
	if sc.HasAnyProduct("postgresql", "postgres") {
		return "postgresql"
	}
	if sc.HasAnyProduct("mssql", "sql server") {
		return "mssql"
	}
	if sc.HasAnyProduct("oracle") {
		return "oracle"
	}
	if sc.HasAnyProduct("sqlite") {
		return "sqlite"
	}
	if sc.HasAnyProduct("mongodb", "mongo") {
		return "mongodb"
	}
	return ""
}

func (sc *ScanContext) DetectedLang() string {
	if sc.HasAnyProduct("php", "wordpress", "laravel", "drupal", "joomla") {
		return "php"
	}
	if sc.HasAnyProduct("python", "django", "flask", "jinja2") {
		return "python"
	}
	if sc.HasAnyProduct("java", "tomcat", "spring", "struts") {
		return "java"
	}
	if sc.HasAnyProduct("node", "express", "next.js", "nuxt") {
		return "node"
	}
	if sc.HasAnyProduct("ruby", "rails") {
		return "ruby"
	}
	if sc.HasAnyProduct("asp.net", "iis", ".net") {
		return "dotnet"
	}
	return ""
}

type WAFBypassEncoder struct {
	wafs []WAFInfo
}

func NewWAFBypassEncoder(sc *ScanContext) *WAFBypassEncoder {
	if sc == nil {
		return &WAFBypassEncoder{}
	}
	return &WAFBypassEncoder{wafs: sc.WAFs}
}

func (e *WAFBypassEncoder) HasWAF() bool {
	return len(e.wafs) > 0
}

func (e *WAFBypassEncoder) EncodePayloads(payloads []string) []string {
	if !e.HasWAF() {
		return payloads
	}

	var result []string
	result = append(result, payloads...)

	for _, p := range payloads {
		result = append(result, e.caseVariation(p))

		if strings.Contains(p, " ") {
			result = append(result, strings.ReplaceAll(p, " ", "/**/"))
			result = append(result, strings.ReplaceAll(p, " ", "%09"))
			result = append(result, strings.ReplaceAll(p, " ", "%0a"))
		}

		if strings.Contains(strings.ToLower(p), "select") || strings.Contains(strings.ToLower(p), "union") {
			result = append(result, e.inlineComment(p))
		}
	}

	return dedupStrings(result)
}

func (e *WAFBypassEncoder) caseVariation(payload string) string {
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP", "SLEEP", "BENCHMARK", "WAITFOR"}
	result := payload
	for _, kw := range keywords {
		lower := strings.ToLower(kw)
		if strings.Contains(strings.ToLower(result), lower) {
			mixed := ""
			for i, c := range lower {
				if i%2 == 0 {
					mixed += strings.ToUpper(string(c))
				} else {
					mixed += string(c)
				}
			}
			result = strings.NewReplacer(kw, mixed, lower, mixed).Replace(result)
		}
	}
	return result
}

func (e *WAFBypassEncoder) inlineComment(payload string) string {
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR"}
	result := payload
	for _, kw := range keywords {
		result = strings.ReplaceAll(result, kw, kw[:len(kw)/2]+"/**/"+kw[len(kw)/2:])
		result = strings.ReplaceAll(result, strings.ToLower(kw), strings.ToLower(kw[:len(kw)/2])+"/**/"+strings.ToLower(kw[len(kw)/2:]))
	}
	return result
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	var result []string
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
