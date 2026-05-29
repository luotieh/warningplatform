package nuclei

import "strings"

// techGroup defines a group of mutually-exclusive technology stack identifiers.
// If ANY member of a group is detected, PoC targeting OTHER groups can be skipped.
var techGroups = [][]string{
	{"php", "laravel", "symfony", "codeigniter", "yii", "cakephp", "drupal", "wordpress", "joomla", "magento", "thinkphp", "phpmyadmin"},
	{"java", "spring", "springboot", "struts", "tomcat", "weblogic", "jboss", "wildfly", "glassfish", "jenkins", "shiro"},
	{"python", "django", "flask", "fastapi", "tornado"},
	{"ruby", "rails", "sinatra"},
	{"node", "nodejs", "express", "next.js", "nextjs", "nuxt"},
	{".net", "asp.net", "aspnet", "dotnet", "iis"},
	{"go", "golang", "gin", "beego"},
}

// genericTags are tags that should never be excluded regardless of detected stack.
var genericTags = map[string]struct{}{
	"sqli": {}, "xss": {}, "ssrf": {}, "rce": {}, "lfi": {},
	"rfi": {}, "xxe": {}, "ssti": {}, "idor": {}, "csrf": {},
	"cve": {}, "network": {}, "ssl": {}, "tls": {}, "dns": {},
	"ftp": {}, "ssh": {}, "smtp": {}, "http": {}, "default-login": {},
	"exposure": {}, "misconfig": {}, "config": {}, "info": {},
	"tech": {}, "token": {}, "auth": {}, "bypass": {},
	"upload": {}, "traversal": {}, "injection": {}, "deserialization": {},
	"oast": {}, "intrusive": {}, "cloud": {}, "aws": {}, "azure": {},
	"panel": {}, "login": {}, "redirect": {}, "cors": {},
	"crlf": {}, "cmdi": {}, "nosqli": {}, "graphql": {},
	"api": {}, "swagger": {}, "openapi": {}, "waf": {},
}

// BuildTechExclusionSet returns a set of tech keywords that should be excluded,
// given the detected products/technologies.
// Returns nil if no meaningful exclusion can be determined (e.g. no language detected).
func BuildTechExclusionSet(detectedProducts []string) map[string]struct{} {
	if len(detectedProducts) == 0 {
		return nil
	}

	dpLower := make(map[string]struct{}, len(detectedProducts))
	for _, p := range detectedProducts {
		dpLower[strings.ToLower(p)] = struct{}{}
	}

	detectedGroups := make(map[int]struct{})
	for i, group := range techGroups {
		for _, tech := range group {
			if _, ok := dpLower[tech]; ok {
				detectedGroups[i] = struct{}{}
				break
			}
		}
	}

	if len(detectedGroups) == 0 {
		return nil
	}

	exclude := make(map[string]struct{})
	for i, group := range techGroups {
		if _, detected := detectedGroups[i]; detected {
			continue
		}
		for _, tech := range group {
			exclude[tech] = struct{}{}
		}
	}

	return exclude
}

// ShouldExcludeByTechStack returns true if the PoC entry's tags indicate it belongs
// to a technology stack that was NOT detected on the target.
func ShouldExcludeByTechStack(entry *PocEntry, exclusionSet map[string]struct{}) bool {
	if exclusionSet == nil {
		return false
	}

	tags := strings.Split(entry.Tags, ",")
	hasTechTag := false
	allTechExcluded := true

	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}

		if _, isGeneric := genericTags[tag]; isGeneric {
			continue
		}

		if _, excluded := exclusionSet[tag]; excluded {
			hasTechTag = true
		} else {
			for _, group := range techGroups {
				for _, tech := range group {
					if tag == tech {
						hasTechTag = true
						allTechExcluded = false
						break
					}
				}
				if !allTechExcluded {
					break
				}
			}
			if !allTechExcluded {
				break
			}
		}
	}

	return hasTechTag && allTechExcluded
}
