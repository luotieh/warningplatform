package rulestore

import "vulnscan-backend/model"

var builtinJSRules = []model.ScanRule{
	// API 路径
	{RuleType: model.RuleTypeJSAnalyze, Name: "REST API Path", Category: "api_path", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: "[\"'`](/api/v[0-9]+/[a-zA-Z0-9/_\\-]+)[\"'`]", Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeJSAnalyze, Name: "API Endpoint", Category: "api_path", Severity: "info", Confidence: 70, MatchLocation: model.MatchLocationBody, MatchPattern: "[\"'`](/[a-zA-Z0-9]+/[a-zA-Z0-9/_\\-]{3,})[\"'`]", Source: "builtin", Priority: 70},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Axios/Fetch URL", Category: "api_path", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationBody, MatchPattern: "(?:axios|fetch|ajax|request)\\s*[.(]\\s*[\"'`]((?:https?://)?[a-zA-Z0-9./_\\-]+)[\"'`]", Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Base URL Config", Category: "api_path", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationBody, MatchPattern: "(?:baseURL|BASE_URL|apiUrl|API_URL|baseUrl)\\s*[:=]\\s*[\"'`](https?://[^\"'`]+)[\"'`]", Source: "builtin", Priority: 90},

	// 密钥/Token
	{RuleType: model.RuleTypeJSAnalyze, Name: "AWS Access Key", Category: "secret", Severity: "critical", Confidence: 95, MatchLocation: model.MatchLocationBody, MatchPattern: `(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}`, Source: "builtin", Priority: 99},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Private Key", Category: "secret", Severity: "critical", Confidence: 99, MatchLocation: model.MatchLocationBody, MatchPattern: `-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`, Source: "builtin", Priority: 99},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Generic API Key", Category: "secret", Severity: "high", Confidence: 80, MatchLocation: model.MatchLocationBody, MatchPattern: "(?i)(?:api[_\\-]?key|apikey|api[_\\-]?secret)\\s*[:=]\\s*[\"'`]([a-zA-Z0-9_\\-]{16,})[\"'`]", Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeJSAnalyze, Name: "JWT Token", Category: "secret", Severity: "high", Confidence: 90, MatchLocation: model.MatchLocationBody, MatchPattern: `eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`, Source: "builtin", Priority: 88},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Bearer Token", Category: "secret", Severity: "high", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: "(?i)(?:bearer|authorization)\\s*[:=]\\s*[\"'`]([a-zA-Z0-9_\\-.]{20,})[\"'`]", Source: "builtin", Priority: 88},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Password Literal", Category: "secret", Severity: "high", Confidence: 75, MatchLocation: model.MatchLocationBody, MatchPattern: "(?i)(?:password|passwd|pwd|secret)\\s*[:=]\\s*[\"'`]([^\"'`]{6,})[\"'`]", Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeJSAnalyze, Name: "OAuth Client Secret", Category: "secret", Severity: "high", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: "(?i)client[_\\-]?secret\\s*[:=]\\s*[\"'`]([a-zA-Z0-9_\\-]{16,})[\"'`]", Source: "builtin", Priority: 88},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Google API Key", Category: "secret", Severity: "high", Confidence: 95, MatchLocation: model.MatchLocationBody, MatchPattern: `AIza[0-9A-Za-z_\-]{35}`, Source: "builtin", Priority: 95},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Slack Token", Category: "secret", Severity: "high", Confidence: 95, MatchLocation: model.MatchLocationBody, MatchPattern: `xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+`, Source: "builtin", Priority: 95},
	{RuleType: model.RuleTypeJSAnalyze, Name: "GitHub Token", Category: "secret", Severity: "high", Confidence: 95, MatchLocation: model.MatchLocationBody, MatchPattern: `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`, Source: "builtin", Priority: 95},

	// 内网 IP
	{RuleType: model.RuleTypeJSAnalyze, Name: "Private IP 10.x", Category: "internal_ip", Severity: "medium", Confidence: 70, MatchLocation: model.MatchLocationBody, MatchPattern: `\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`, Source: "builtin", Priority: 70},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Private IP 172.x", Category: "internal_ip", Severity: "medium", Confidence: 70, MatchLocation: model.MatchLocationBody, MatchPattern: `\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`, Source: "builtin", Priority: 70},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Private IP 192.168.x", Category: "internal_ip", Severity: "medium", Confidence: 70, MatchLocation: model.MatchLocationBody, MatchPattern: `\b192\.168\.\d{1,3}\.\d{1,3}\b`, Source: "builtin", Priority: 70},

	// 云存储
	{RuleType: model.RuleTypeJSAnalyze, Name: "S3 Bucket", Category: "cloud", Severity: "medium", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `[a-z0-9][a-z0-9.\-]{1,61}\.s3[.\-][a-z0-9.\-]*\.com`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Azure Blob", Category: "cloud", Severity: "medium", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `https?://[a-z0-9]+\.blob\.core\.windows\.net`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Aliyun OSS", Category: "cloud", Severity: "medium", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `https?://[a-z0-9\-]+\.oss-[a-z0-9\-]+\.aliyuncs\.com`, Source: "builtin", Priority: 80},

	// Debug
	{RuleType: model.RuleTypeJSAnalyze, Name: "Source Map", Category: "debug", Severity: "low", Confidence: 90, MatchLocation: model.MatchLocationBody, MatchPattern: `//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)`, Source: "builtin", Priority: 75},

	// 敏感路径
	{RuleType: model.RuleTypeJSAnalyze, Name: "Admin Path", Category: "path", Severity: "medium", Confidence: 75, MatchLocation: model.MatchLocationBody, MatchPattern: "[\"'`](/(?:admin|manage|dashboard|console|backend|internal)/[^\"'`]*)[\"'`]", Source: "builtin", Priority: 75},
	{RuleType: model.RuleTypeJSAnalyze, Name: "Upload Path", Category: "path", Severity: "low", Confidence: 70, MatchLocation: model.MatchLocationBody, MatchPattern: "[\"'`](/(?:upload|file|attachment|media)/[^\"'`]*)[\"'`]", Source: "builtin", Priority: 70},
}
