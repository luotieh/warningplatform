package engine

import (
	"log/slog"
	"strings"
)

type TechStack string

const (
	TechPHP     TechStack = "php"
	TechJava    TechStack = "java"
	TechPython  TechStack = "python"
	TechNode    TechStack = "node"
	TechASPNET  TechStack = "aspnet"
	TechRuby    TechStack = "ruby"
	TechGo      TechStack = "go"
	TechGeneric TechStack = "generic"
)

type TechProfile struct {
	Stack            TechStack              `json:"stack"`
	Framework        string                 `json:"framework"`
	Server           string                 `json:"server"`
	RecommendModules []string               `json:"recommend_modules"`
	SkipModules      []string               `json:"skip_modules"`
	HighPriority     []string               `json:"high_priority"`
	ExtraConfig      map[string]interface{} `json:"extra_config"`
}

type StrategyEngine struct {
	profiles map[TechStack]*TechProfile
}

func NewStrategyEngine() *StrategyEngine {
	se := &StrategyEngine{
		profiles: make(map[TechStack]*TechProfile),
	}
	se.registerDefaults()
	return se
}

func (se *StrategyEngine) DetectTechStack(findings []*Finding, targets []*Target) TechStack {
	techScores := make(map[TechStack]int)

	for _, f := range findings {
		lower := strings.ToLower(f.Title + " " + f.Description)
		data := ""
		if f.Data != nil {
			for _, v := range f.Data {
				data += " " + strings.ToLower(v)
			}
		}
		combined := lower + data

		if containsAny(combined, "php", "laravel", "wordpress", "drupal", "joomla", "codeigniter", "symfony", "x-powered-by: php") {
			techScores[TechPHP] += 3
		}
		if containsAny(combined, "java", "spring", "struts", "tomcat", "weblogic", "jboss", "wildfly", "jsf", "servlet", ".jsp", ".do", ".action") {
			techScores[TechJava] += 3
		}
		if containsAny(combined, "python", "django", "flask", "fastapi", "tornado", "gunicorn", "werkzeug", "uvicorn") {
			techScores[TechPython] += 3
		}
		if containsAny(combined, "node", "express", "next.js", "nuxt", "koa", "nestjs", "x-powered-by: express") {
			techScores[TechNode] += 3
		}
		if containsAny(combined, "asp.net", "iis", ".aspx", ".ashx", ".asmx", "microsoft", "blazor") {
			techScores[TechASPNET] += 3
		}
		if containsAny(combined, "ruby", "rails", "sinatra", "phusion", "passenger", "rack") {
			techScores[TechRuby] += 3
		}
		if containsAny(combined, "golang", "gin", "echo", "fiber", "beego") {
			techScores[TechGo] += 2
		}
	}

	for _, t := range targets {
		if t.Extra != nil {
			for _, v := range t.Extra {
				lower := strings.ToLower(v)
				if containsAny(lower, "php") {
					techScores[TechPHP] += 2
				}
				if containsAny(lower, "java", "tomcat") {
					techScores[TechJava] += 2
				}
				if containsAny(lower, "python", "django") {
					techScores[TechPython] += 2
				}
			}
		}
	}

	var bestStack TechStack = TechGeneric
	bestScore := 0
	for stack, score := range techScores {
		if score > bestScore {
			bestStack = stack
			bestScore = score
		}
	}

	if bestScore >= 2 {
		slog.Info("[Strategy] 检测到技术栈", "stack", bestStack, "score", bestScore)
		return bestStack
	}

	return TechGeneric
}

func (se *StrategyEngine) GetProfile(stack TechStack) *TechProfile {
	if p, ok := se.profiles[stack]; ok {
		return p
	}
	return se.profiles[TechGeneric]
}

func (se *StrategyEngine) FilterModules(modules []ScanModule, stack TechStack) []ScanModule {
	profile := se.GetProfile(stack)
	if profile == nil {
		return modules
	}

	skipSet := make(map[string]bool)
	for _, id := range profile.SkipModules {
		skipSet[id] = true
	}

	prioritySet := make(map[string]bool)
	for _, id := range profile.HighPriority {
		prioritySet[id] = true
	}

	var highPri, normal, rest []ScanModule
	for _, m := range modules {
		if skipSet[m.ID()] {
			slog.Debug("[Strategy] 跳过不适用模块", "module", m.ID(), "stack", stack)
			continue
		}
		if prioritySet[m.ID()] {
			highPri = append(highPri, m)
		} else {
			normal = append(normal, m)
		}
	}

	rest = append(highPri, normal...)

	slog.Info("[Strategy] 模块过滤完成",
		"stack", stack,
		"total", len(modules),
		"filtered", len(rest),
		"high_priority", len(highPri),
	)

	return rest
}

func (se *StrategyEngine) registerDefaults() {
	se.profiles[TechPHP] = &TechProfile{
		Stack:     TechPHP,
		Framework: "PHP",
		HighPriority: []string{
			"sqli", "lfi", "cmdi", "xss",
		},
		RecommendModules: []string{
			"sqli", "xss", "lfi", "cmdi", "ssrf", "dirscan", "weakpass",
		},
		ExtraConfig: map[string]interface{}{
			"lfi_php_filter": true,
		},
	}

	se.profiles[TechJava] = &TechProfile{
		Stack:     TechJava,
		Framework: "Java",
		HighPriority: []string{
			"sqli", "ssrf", "cmdi",
		},
		RecommendModules: []string{
			"sqli", "ssrf", "cmdi", "xss", "dirscan", "infoleak",
		},
		ExtraConfig: map[string]interface{}{
			"sqli_dialects": []string{"oracle", "mysql", "postgresql"},
		},
	}

	se.profiles[TechPython] = &TechProfile{
		Stack:     TechPython,
		Framework: "Python",
		HighPriority: []string{
			"cmdi", "ssrf", "sqli",
		},
		RecommendModules: []string{
			"cmdi", "ssrf", "sqli", "xss", "infoleak",
		},
		ExtraConfig: map[string]interface{}{
			"ssrf_redirect_follow": true,
		},
	}

	se.profiles[TechNode] = &TechProfile{
		Stack:     TechNode,
		Framework: "Node.js",
		HighPriority: []string{
			"xss", "ssrf", "sqli",
		},
		RecommendModules: []string{
			"xss", "ssrf", "sqli", "cmdi", "infoleak",
		},
	}

	se.profiles[TechASPNET] = &TechProfile{
		Stack:     TechASPNET,
		Framework: "ASP.NET",
		HighPriority: []string{
			"sqli", "xss", "lfi",
		},
		RecommendModules: []string{
			"sqli", "xss", "lfi", "dirscan", "infoleak",
		},
		ExtraConfig: map[string]interface{}{
			"lfi_win_paths": true,
		},
	}

	se.profiles[TechRuby] = &TechProfile{
		Stack:     TechRuby,
		Framework: "Ruby",
		HighPriority: []string{
			"cmdi", "sqli", "xss",
		},
	}

	se.profiles[TechGo] = &TechProfile{
		Stack:     TechGo,
		Framework: "Go",
		HighPriority: []string{
			"ssrf", "cmdi",
		},
	}

	se.profiles[TechGeneric] = &TechProfile{
		Stack:     TechGeneric,
		Framework: "Generic",
		HighPriority: []string{
			"sqli", "xss", "cmdi", "ssrf", "lfi",
		},
	}
}

func containsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}
