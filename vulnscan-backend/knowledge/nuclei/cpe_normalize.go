package nuclei

import (
	"strings"
)

// cpeAlias maps common product name variants to a canonical form.
// This improves matching accuracy between fingerprint output and PoC metadata.
var cpeAlias = map[string]string{
	"httpd":                         "apache http server",
	"apache httpd":                  "apache http server",
	"apache/httpd":                  "apache http server",
	"apache2":                       "apache http server",
	"apache web server":             "apache http server",
	"nginx":                         "nginx",
	"nginx/":                        "nginx",
	"openresty":                     "nginx",
	"iis":                           "microsoft iis",
	"microsoft-iis":                 "microsoft iis",
	"internet information services": "microsoft iis",
	"tomcat":                        "apache tomcat",
	"apache tomcat":                 "apache tomcat",
	"apache-tomcat":                 "apache tomcat",
	"weblogic":                      "oracle weblogic server",
	"oracle weblogic":               "oracle weblogic server",
	"weblogic server":               "oracle weblogic server",
	"jboss":                         "redhat jboss",
	"jboss eap":                     "redhat jboss",
	"wildfly":                       "redhat wildfly",
	"jetty":                         "eclipse jetty",
	"lighttpd":                      "lighttpd",
	"caddy":                         "caddy",
	"haproxy":                       "haproxy",
	"php":                           "php",
	"php/":                          "php",
	"wordpress":                     "wordpress",
	"wp":                            "wordpress",
	"joomla":                        "joomla",
	"joomla!":                       "joomla",
	"drupal":                        "drupal",
	"laravel":                       "laravel",
	"symfony":                       "symfony",
	"codeigniter":                   "codeigniter",
	"django":                        "django",
	"flask":                         "flask",
	"express":                       "express",
	"express.js":                    "express",
	"next.js":                       "nextjs",
	"nextjs":                        "nextjs",
	"nuxt":                          "nuxtjs",
	"nuxt.js":                       "nuxtjs",
	"spring":                        "spring framework",
	"spring boot":                   "spring boot",
	"spring-boot":                   "spring boot",
	"springboot":                    "spring boot",
	"struts":                        "apache struts",
	"apache struts":                 "apache struts",
	"rails":                         "ruby on rails",
	"ruby on rails":                 "ruby on rails",
	"ror":                           "ruby on rails",
	"mysql":                         "mysql",
	"mariadb":                       "mariadb",
	"postgresql":                    "postgresql",
	"postgres":                      "postgresql",
	"mssql":                         "microsoft sql server",
	"sql server":                    "microsoft sql server",
	"sqlserver":                     "microsoft sql server",
	"oracle db":                     "oracle database",
	"oracle database":               "oracle database",
	"mongodb":                       "mongodb",
	"mongo":                         "mongodb",
	"redis":                         "redis",
	"memcached":                     "memcached",
	"elasticsearch":                 "elasticsearch",
	"elastic":                       "elasticsearch",
	"kibana":                        "kibana",
	"grafana":                       "grafana",
	"prometheus":                    "prometheus",
	"rabbitmq":                      "rabbitmq",
	"activemq":                      "apache activemq",
	"kafka":                         "apache kafka",
	"zookeeper":                     "apache zookeeper",
	"jenkins":                       "jenkins",
	"gitlab":                        "gitlab",
	"github enterprise":             "github enterprise",
	"sonarqube":                     "sonarqube",
	"confluence":                    "atlassian confluence",
	"jira":                          "atlassian jira",
	"bamboo":                        "atlassian bamboo",
	"bitbucket":                     "atlassian bitbucket",
	"openssh":                       "openssh",
	"ssh":                           "openssh",
	"openssl":                       "openssl",
	"proftpd":                       "proftpd",
	"vsftpd":                        "vsftpd",
	"pureftpd":                      "pure-ftpd",
	"bind":                          "isc bind",
	"isc bind":                      "isc bind",
	"named":                         "isc bind",
	"docker":                        "docker",
	"kubernetes":                    "kubernetes",
	"k8s":                           "kubernetes",
	"vmware":                        "vmware",
	"esxi":                          "vmware esxi",
	"vcenter":                       "vmware vcenter",
	"fortinet":                      "fortinet fortigate",
	"fortigate":                     "fortinet fortigate",
	"paloalto":                      "palo alto",
	"sonicwall":                     "sonicwall",
	"cisco asa":                     "cisco asa",
	"f5 big-ip":                     "f5 big-ip",
	"big-ip":                        "f5 big-ip",
	"citrix":                        "citrix adc",
	"netscaler":                     "citrix adc",
	"nagios":                        "nagios",
	"zabbix":                        "zabbix",
	"phpmyadmin":                    "phpmyadmin",
	"adminer":                       "adminer",
}

// NormalizeProduct converts a raw product name to a canonical form.
func NormalizeProduct(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return ""
	}

	// Direct alias lookup
	if canonical, ok := cpeAlias[lower]; ok {
		return canonical
	}

	// Strip version suffix (e.g., "nginx/1.21.0" → "nginx")
	if idx := strings.IndexByte(lower, '/'); idx > 0 {
		prefix := lower[:idx]
		if canonical, ok := cpeAlias[prefix]; ok {
			return canonical
		}
		return prefix
	}

	return lower
}

// NormalizeProductList normalizes a list of product names, deduplicating the results.
func NormalizeProductList(products []string) []string {
	seen := make(map[string]struct{}, len(products))
	var result []string

	for _, p := range products {
		normalized := NormalizeProduct(p)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; !exists {
			seen[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}

	return result
}

// ProductMatchScore returns a match score (0-100) between two product names.
// Higher scores indicate stronger matches.
func ProductMatchScore(detected, pocProduct string) int {
	d := NormalizeProduct(detected)
	p := NormalizeProduct(pocProduct)

	if d == "" || p == "" {
		return 0
	}

	if d == p {
		return 100
	}

	// Check if one contains the other
	if strings.Contains(d, p) || strings.Contains(p, d) {
		longerLen := len(d)
		if len(p) > longerLen {
			longerLen = len(p)
		}
		shorterLen := len(d)
		if len(p) < shorterLen {
			shorterLen = len(p)
		}
		// Scale based on length ratio
		return 50 + int(float64(shorterLen)/float64(longerLen)*50)
	}

	// Word overlap
	dWords := strings.Fields(d)
	pWords := strings.Fields(p)
	overlap := 0
	for _, dw := range dWords {
		for _, pw := range pWords {
			if dw == pw {
				overlap++
				break
			}
		}
	}
	totalWords := len(dWords)
	if len(pWords) > totalWords {
		totalWords = len(pWords)
	}
	if totalWords > 0 && overlap > 0 {
		return int(float64(overlap) / float64(totalWords) * 60)
	}

	return 0
}
