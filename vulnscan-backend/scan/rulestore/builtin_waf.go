package rulestore

import "vulnscan-backend/model"

var builtinWAFRules = []model.ScanRule{
	// Cloudflare
	{RuleType: model.RuleTypeWAFDetect, Name: "Cloudflare", Category: "cdn_waf", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)cloudflare`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeWAFDetect, Name: "Cloudflare Cf-Ray", Category: "cdn_waf", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Cf-Ray", MatchPattern: `.+`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeWAFDetect, Name: "Cloudflare Cookie", Category: "cdn_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)__cfduid|cf_clearance`, Source: "builtin", Priority: 85},

	// AWS WAF
	{RuleType: model.RuleTypeWAFDetect, Name: "AWS WAF", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Amzn-Requestid", MatchPattern: `.+`, Source: "builtin", Priority: 85},

	// Akamai
	{RuleType: model.RuleTypeWAFDetect, Name: "Akamai Kona", Category: "cdn_waf", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)AkamaiGHost|AkamaiNetStorage`, Source: "builtin", Priority: 90},

	// Imperva/Incapsula
	{RuleType: model.RuleTypeWAFDetect, Name: "Imperva Incapsula", Category: "cloud_waf", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)incap_ses|visid_incap`, Source: "builtin", Priority: 90},

	// Sucuri
	{RuleType: model.RuleTypeWAFDetect, Name: "Sucuri", Category: "cloud_waf", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Sucuri`, Source: "builtin", Priority: 90},

	// F5 BIG-IP
	{RuleType: model.RuleTypeWAFDetect, Name: "F5 BIG-IP ASM", Category: "hardware_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)BigIP|BIG-IP|F5`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeWAFDetect, Name: "F5 BIG-IP Cookie", Category: "hardware_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)BIGipServer|TS[0-9a-f]{8}`, Source: "builtin", Priority: 85},

	// ModSecurity
	{RuleType: model.RuleTypeWAFDetect, Name: "ModSecurity", Category: "oss_waf", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)mod_security|modsecurity`, Source: "builtin", Priority: 90},

	// Fortinet
	{RuleType: model.RuleTypeWAFDetect, Name: "Fortinet FortiWeb", Category: "hardware_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)FortiWeb`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeWAFDetect, Name: "Fortinet Cookie", Category: "hardware_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)FORTIWAFSID`, Source: "builtin", Priority: 85},

	// Citrix NetScaler
	{RuleType: model.RuleTypeWAFDetect, Name: "Citrix NetScaler", Category: "hardware_waf", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationHeader, MatchKey: "Via", MatchPattern: `(?i)NS-CACHE`, Source: "builtin", Priority: 80},

	// Azure Front Door
	{RuleType: model.RuleTypeWAFDetect, Name: "Azure Front Door", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Azure-Ref", MatchPattern: `.+`, Source: "builtin", Priority: 85},

	// 阿里云盾
	{RuleType: model.RuleTypeWAFDetect, Name: "阿里云盾 YunDun", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Yundun|Alibaba|Tengine`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeWAFDetect, Name: "阿里云盾 Cookie", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)aliyungf_tc`, Source: "builtin", Priority: 85},

	// 腾讯云 WAF
	{RuleType: model.RuleTypeWAFDetect, Name: "腾讯云 WAF", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)TencentWAF|TSA`, Source: "builtin", Priority: 85},

	// 安全狗
	{RuleType: model.RuleTypeWAFDetect, Name: "安全狗 SafeDog", Category: "software_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)safe[-_ ]?dog|WAF/2\.0`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeWAFDetect, Name: "安全狗 Cookie", Category: "software_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)safedog-flow-item`, Source: "builtin", Priority: 85},

	// 长亭雷池
	{RuleType: model.RuleTypeWAFDetect, Name: "长亭雷池 SafeLine", Category: "software_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)SafeLine|ASERVER`, Source: "builtin", Priority: 85},

	// 360 WAF
	{RuleType: model.RuleTypeWAFDetect, Name: "360 WAF Header", Category: "software_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Powered-By-360wzb", MatchPattern: `.+`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeWAFDetect, Name: "360 WAF Cookie", Category: "software_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)360wzws_cid`, Source: "builtin", Priority: 85},

	// 绿盟
	{RuleType: model.RuleTypeWAFDetect, Name: "绿盟 WAF", Category: "hardware_waf", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)NSFOCUS`, Source: "builtin", Priority: 80},

	// 宝塔
	{RuleType: model.RuleTypeWAFDetect, Name: "宝塔 BT Panel", Category: "software_waf", Severity: "info", Confidence: 75, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)宝塔|bt\.cn|btpanel`, Source: "builtin", Priority: 75},

	// Wordfence
	{RuleType: model.RuleTypeWAFDetect, Name: "Wordfence", Category: "software_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)generated by Wordfence|wordfence`, Source: "builtin", Priority: 85},

	// Wallarm
	{RuleType: model.RuleTypeWAFDetect, Name: "Wallarm", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)wallarm`, Source: "builtin", Priority: 85},

	// Fastly
	{RuleType: model.RuleTypeWAFDetect, Name: "Fastly CDN", Category: "cdn_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Fastly-Request-Id", MatchPattern: `.+`, Source: "builtin", Priority: 85},

	// Reblaze
	{RuleType: model.RuleTypeWAFDetect, Name: "Reblaze", Category: "cloud_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)rbzid`, Source: "builtin", Priority: 85},

	// StackPath
	{RuleType: model.RuleTypeWAFDetect, Name: "StackPath", Category: "cdn_waf", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Sp-Waf-Id", MatchPattern: `.+`, Source: "builtin", Priority: 85},
}
