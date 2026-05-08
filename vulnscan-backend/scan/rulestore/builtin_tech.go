package rulestore

import "vulnscan-backend/model"

var builtinTechRules = []model.ScanRule{
	// --- CMS ---
	{RuleType: model.RuleTypeTechDetect, Name: "WordPress", Category: "CMS", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)/wp-content/|/wp-includes/|wp-json`, VersionPattern: `(?i)WordPress\s*([0-9.]+)`, Implies: model.StringArray{"PHP", "MySQL"}, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "WordPress Meta", Category: "CMS", Severity: "info", Confidence: 92, MatchLocation: model.MatchLocationMeta, MatchKey: "generator", MatchPattern: `(?i)WordPress`, VersionPattern: `(?i)WordPress\s*([0-9.]+)`, Implies: model.StringArray{"PHP", "MySQL"}, Source: "builtin", Priority: 92},
	{RuleType: model.RuleTypeTechDetect, Name: "Drupal", Category: "CMS", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationMeta, MatchKey: "generator", MatchPattern: `(?i)Drupal`, Implies: model.StringArray{"PHP"}, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "Joomla", Category: "CMS", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationMeta, MatchKey: "generator", MatchPattern: `(?i)Joomla`, Implies: model.StringArray{"PHP"}, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "Shopify", Category: "CMS", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)cdn\.shopify\.com`, Implies: model.StringArray{"Ruby"}, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Ghost", Category: "CMS", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationMeta, MatchKey: "generator", MatchPattern: `(?i)Ghost`, Implies: model.StringArray{"Node.js"}, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "Hugo", Category: "CMS", Severity: "info", Confidence: 88, MatchLocation: model.MatchLocationMeta, MatchKey: "generator", MatchPattern: `(?i)Hugo`, Source: "builtin", Priority: 88},
	{RuleType: model.RuleTypeTechDetect, Name: "Hexo", Category: "CMS", Severity: "info", Confidence: 88, MatchLocation: model.MatchLocationMeta, MatchKey: "generator", MatchPattern: `(?i)Hexo`, Source: "builtin", Priority: 88},

	// --- Server ---
	{RuleType: model.RuleTypeTechDetect, Name: "Nginx", Category: "Server", Severity: "info", Confidence: 95, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)nginx`, VersionPattern: `(?i)nginx/([0-9.]+)`, Source: "builtin", Priority: 95},
	{RuleType: model.RuleTypeTechDetect, Name: "Apache", Category: "Server", Severity: "info", Confidence: 95, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Apache`, VersionPattern: `(?i)Apache/([0-9.]+)`, Source: "builtin", Priority: 95},
	{RuleType: model.RuleTypeTechDetect, Name: "IIS", Category: "Server", Severity: "info", Confidence: 95, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Microsoft-IIS`, VersionPattern: `(?i)IIS/([0-9.]+)`, Source: "builtin", Priority: 95},
	{RuleType: model.RuleTypeTechDetect, Name: "LiteSpeed", Category: "Server", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)LiteSpeed`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "OpenResty", Category: "Server", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)openresty`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "Caddy", Category: "Server", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Caddy`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "Tengine", Category: "Server", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Tengine`, Source: "builtin", Priority: 90},

	// --- Language ---
	{RuleType: model.RuleTypeTechDetect, Name: "PHP", Category: "Language", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Powered-By", MatchPattern: `(?i)PHP`, VersionPattern: `(?i)PHP/([0-9.]+)`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "ASP.NET", Category: "Language", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Powered-By", MatchPattern: `(?i)ASP\.NET`, VersionPattern: `(?i)ASP\.NET\s+Version:([0-9.]+)`, Source: "builtin", Priority: 90},
	{RuleType: model.RuleTypeTechDetect, Name: "Java", Category: "Language", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)JSESSIONID`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Python", Category: "Language", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)WSGIServer|gunicorn|uvicorn|waitress`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Node.js", Category: "Language", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Powered-By", MatchPattern: `(?i)Express`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Ruby", Category: "Language", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Passenger|WEBrick`, Source: "builtin", Priority: 85},

	// --- Framework ---
	{RuleType: model.RuleTypeTechDetect, Name: "Laravel", Category: "Framework", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)laravel_session`, Implies: model.StringArray{"PHP"}, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Spring", Category: "Framework", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationHeader, MatchKey: "X-Application-Context", MatchPattern: `.+`, Implies: model.StringArray{"Java"}, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeTechDetect, Name: "Ruby on Rails", Category: "Framework", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationCookie, MatchPattern: `(?i)_rails_session|_session_id`, Implies: model.StringArray{"Ruby"}, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Next.js", Category: "Framework", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)_next/static|__NEXT_DATA__`, Implies: model.StringArray{"React", "Node.js"}, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Nuxt.js", Category: "Framework", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)_nuxt/|__NUXT__`, Implies: model.StringArray{"Vue.js", "Node.js"}, Source: "builtin", Priority: 85},

	// --- JavaScript ---
	{RuleType: model.RuleTypeTechDetect, Name: "React", Category: "JavaScript", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)react\.production\.min|_reactRootContainer|data-reactid`, VersionPattern: `(?i)react[.-]([0-9.]+)`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Vue.js", Category: "JavaScript", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)Vue\.js|v-cloak|data-v-[a-f0-9]`, VersionPattern: `(?i)vue[.-]([0-9.]+)`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Angular", Category: "JavaScript", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)ng-version|ng-app|angular\.min\.js`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "jQuery", Category: "JavaScript", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationScript, MatchPattern: `(?i)jquery[.-]([0-9.]+)`, VersionPattern: `(?i)jQuery\s+v?([0-9.]+)`, Source: "builtin", Priority: 85},

	// --- UI Framework ---
	{RuleType: model.RuleTypeTechDetect, Name: "Bootstrap", Category: "UI Framework", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)bootstrap\.min\.(css|js)`, VersionPattern: `(?i)Bootstrap\s+v?([0-9.]+)`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "Tailwind CSS", Category: "UI Framework", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)tailwindcss|tailwind\.min\.css`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeTechDetect, Name: "Ant Design", Category: "UI Framework", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)antd|ant-design`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeTechDetect, Name: "Element UI", Category: "UI Framework", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)element-ui|ElementUI`, Source: "builtin", Priority: 80},

	// --- Build Tool ---
	{RuleType: model.RuleTypeTechDetect, Name: "Webpack", Category: "Build Tool", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)webpackJsonp|__webpack_require__`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeTechDetect, Name: "Vite", Category: "Build Tool", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)/@vite/client|/vite/`, Source: "builtin", Priority: 80},

	// --- CDN ---
	{RuleType: model.RuleTypeTechDetect, Name: "Cloudflare CDN", Category: "CDN", Severity: "info", Confidence: 90, MatchLocation: model.MatchLocationHeader, MatchKey: "Cf-Ray", MatchPattern: `.+`, Source: "builtin", Priority: 90},

	// --- Analytics ---
	{RuleType: model.RuleTypeTechDetect, Name: "Google Analytics", Category: "Analytics", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)google-analytics\.com/analytics\.js|gtag|UA-[0-9]+-[0-9]+`, Source: "builtin", Priority: 85},
	{RuleType: model.RuleTypeTechDetect, Name: "百度统计", Category: "Analytics", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)hm\.baidu\.com/hm\.js`, Source: "builtin", Priority: 85},

	// --- Cache ---
	{RuleType: model.RuleTypeTechDetect, Name: "Varnish", Category: "Cache", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationHeader, MatchKey: "Via", MatchPattern: `(?i)varnish`, Source: "builtin", Priority: 85},

	// --- Security ---
	{RuleType: model.RuleTypeTechDetect, Name: "reCAPTCHA", Category: "Security", Severity: "info", Confidence: 85, MatchLocation: model.MatchLocationBody, MatchPattern: `(?i)recaptcha|google\.com/recaptcha`, Source: "builtin", Priority: 85},

	// --- OS ---
	{RuleType: model.RuleTypeTechDetect, Name: "Ubuntu", Category: "OS", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Ubuntu`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeTechDetect, Name: "Debian", Category: "OS", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)Debian`, Source: "builtin", Priority: 80},
	{RuleType: model.RuleTypeTechDetect, Name: "CentOS", Category: "OS", Severity: "info", Confidence: 80, MatchLocation: model.MatchLocationHeader, MatchKey: "Server", MatchPattern: `(?i)CentOS`, Source: "builtin", Priority: 80},
}
