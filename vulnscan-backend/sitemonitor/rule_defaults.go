package sitemonitor

import (
	"context"
	"encoding/json"
	"log/slog"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

func InitDefaultRuleData(database *db.DB) {
	session, err := database.GetDBSession()
	if err != nil {
		slog.Error("[RuleData] 无法获取数据库会话", "error", err)
		return
	}
	ctx := context.Background()
	for moduleKey, defaultData := range defaultRuleDataMap {
		var existing model.MonitorRuleData
		if session.WithContext(ctx).Where("module_key = ?", moduleKey).First(&existing).Error == nil {
			if existing.Data != "" {
				continue
			}
		}
		raw, _ := json.Marshal(defaultData)
		encoded, err := model.MonitorEncodeRuleData(string(raw))
		if err != nil {
			slog.Error("[RuleData] 编码默认数据失败", "module", moduleKey, "error", err)
			continue
		}
		result := session.WithContext(ctx).Where("module_key = ?", moduleKey).
			Assign(model.MonitorRuleData{Data: encoded}).
			FirstOrCreate(&model.MonitorRuleData{ModuleKey: moduleKey, Data: encoded})
		if result.Error != nil {
			slog.Error("[RuleData] 初始化失败", "module", moduleKey, "error", result.Error)
		} else {
			slog.Info("[RuleData] 初始化默认规则", "module", moduleKey)
		}
	}

	migrateModuleMerge(session, ctx)
}

func migrateModuleMerge(session *gorm.DB, ctx context.Context) {
	merges := []struct {
		from   string
		to     string
		prefix string
	}{
		{from: "backdoor", to: "blacklink", prefix: "backdoor_code_"},
		{from: "backdoor_path", to: "blacklink", prefix: "backdoor_"},
		{from: "malicious_domain", to: "malware", prefix: "malicious_domains_"},
	}

	for _, m := range merges {
		var src model.MonitorRuleData
		if session.WithContext(ctx).Where("module_key = ?", m.from).First(&src).Error != nil {
			continue
		}
		if src.Data == "" {
			session.WithContext(ctx).Where("module_key = ?", m.from).Delete(&model.MonitorRuleData{})
			continue
		}

		decoded, err := model.MonitorDecodeRuleData(src.Data)
		if err != nil {
			continue
		}
		var srcData map[string]any
		if json.Unmarshal([]byte(decoded), &srcData) != nil || len(srcData) == 0 {
			session.WithContext(ctx).Where("module_key = ?", m.from).Delete(&model.MonitorRuleData{})
			continue
		}

		var dst model.MonitorRuleData
		if session.WithContext(ctx).Where("module_key = ?", m.to).First(&dst).Error != nil {
			continue
		}
		dstDecoded, err := model.MonitorDecodeRuleData(dst.Data)
		if err != nil {
			continue
		}
		var dstData map[string]any
		if json.Unmarshal([]byte(dstDecoded), &dstData) != nil {
			dstData = make(map[string]any)
		}

		merged := false
		for k, v := range srcData {
			newKey := m.prefix + k
			if m.from == "backdoor_path" && k == "entries" {
				newKey = "backdoor_paths"
			}
			if m.from == "backdoor" && k == "rules" {
				newKey = "backdoor_code_rules"
			}
			if _, exists := dstData[newKey]; !exists {
				dstData[newKey] = v
				merged = true
			}
		}

		if merged {
			raw, _ := json.Marshal(dstData)
			encoded, err := model.MonitorEncodeRuleData(string(raw))
			if err != nil {
				continue
			}
			session.WithContext(ctx).Model(&model.MonitorRuleData{}).
				Where("module_key = ?", m.to).Update("data", encoded)
			slog.Info("[RuleData] 模块合并迁移完成", "from", m.from, "to", m.to)
		}

		session.WithContext(ctx).Where("module_key = ?", m.from).Delete(&model.MonitorRuleData{})
	}
}

var defaultRuleDataMap = map[string]map[string]any{
	"common": {
		"public_dns": []map[string]string{
			{"ip": "114.114.114.114", "name": "114DNS"},
			{"ip": "223.5.5.5", "name": "阿里DNS"},
			{"ip": "119.29.29.29", "name": "腾讯DNS"},
			{"ip": "180.76.76.76", "name": "百度DNS"},
			{"ip": "8.8.8.8", "name": "Google DNS"},
			{"ip": "1.1.1.1", "name": "Cloudflare DNS"},
		},
	},
	"availability": {
		"tls_ciphers": []map[string]string{
			{"name": "RC4", "description": "已废弃的弱加密算法", "severity": "high"},
			{"name": "DES", "description": "已废弃的弱加密算法", "severity": "high"},
			{"name": "3DES", "description": "不推荐使用的加密算法", "severity": "medium"},
			{"name": "NULL", "description": "无加密", "severity": "critical"},
			{"name": "EXPORT", "description": "出口级弱加密", "severity": "critical"},
		},
		"tls_versions": []map[string]string{
			{"name": "SSLv2", "description": "严重不安全", "severity": "critical"},
			{"name": "SSLv3", "description": "POODLE漏洞", "severity": "critical"},
			{"name": "TLSv1.0", "description": "已废弃", "severity": "high"},
			{"name": "TLSv1.1", "description": "即将废弃", "severity": "medium"},
		},
		"cert_check": []map[string]string{
			{"name": "自签名证书", "description": "证书未经CA签发", "severity": "high"},
			{"name": "证书过期", "description": "证书已过有效期", "severity": "critical"},
			{"name": "域名不匹配", "description": "证书域名与访问域名不一致", "severity": "high"},
			{"name": "弱签名算法", "description": "使用SHA-1等弱签名算法", "severity": "medium"},
			{"name": "证书即将过期(30天)", "description": "证书有效期不足30天", "severity": "medium"},
		},
		"http_headers_check": []map[string]string{
			{"name": "Strict-Transport-Security", "description": "缺少HSTS头", "severity": "medium"},
			{"name": "Content-Security-Policy", "description": "缺少CSP头", "severity": "medium"},
			{"name": "X-Content-Type-Options", "description": "缺少MIME嗅探保护", "severity": "low"},
			{"name": "X-Frame-Options", "description": "缺少点击劫持保护", "severity": "medium"},
			{"name": "X-XSS-Protection", "description": "缺少XSS过滤器", "severity": "low"},
			{"name": "Referrer-Policy", "description": "缺少引用策略", "severity": "low"},
			{"name": "Permissions-Policy", "description": "缺少权限策略", "severity": "low"},
		},
		"info_leak_headers": []map[string]string{
			{"name": "Server", "description": "暴露Web服务器信息", "severity": "low"},
			{"name": "X-Powered-By", "description": "暴露后端技术栈", "severity": "low"},
			{"name": "X-AspNet-Version", "description": "暴露.NET版本", "severity": "medium"},
			{"name": "X-AspNetMvc-Version", "description": "暴露MVC版本", "severity": "medium"},
		},
	},
	"domain_hijack": {
		"hijack_patterns": []map[string]string{
			{"pattern": "(?i)(parking|parked|domain.*(sale|sell|buy))", "name": "域名停靠", "description": "域名被停靠/出售", "severity": "high"},
			{"pattern": "(?i)(this domain|has expired|renew)", "name": "域名过期", "description": "域名已过期", "severity": "critical"},
			{"pattern": "(?i)(suspended|blocked|seized)", "name": "域名被封", "description": "域名被暂停/封禁", "severity": "critical"},
			{"pattern": "(?i)(coming soon|under construction)", "name": "建设中", "description": "页面处于建设状态", "severity": "medium"},
		},
		"hijack_titles": []map[string]string{
			{"title": "域名出售", "description": "域名出售页面"},
			{"title": "domain for sale", "description": "Domain for sale page"},
			{"title": "此域名可出售", "description": "域名可购买"},
			{"title": "域名已过期", "description": "域名过期"},
			{"title": "website expired", "description": "Website expired"},
			{"title": "page not found", "description": "页面未找到"},
			{"title": "此网站正在建设中", "description": "网站建设中"},
			{"title": "under construction", "description": "Under construction"},
		},
		"parking_ips": []map[string]string{
			{"ip": "0.0.0.0", "description": "零地址"},
			{"ip": "127.0.0.1", "description": "本地回环"},
			{"ip": "198.105.254.11", "description": "Sinkhole IP"},
			{"ip": "198.105.254.228", "description": "Sinkhole IP"},
		},
	},
	"tamper": {
		"noise_patterns": []map[string]string{
			{"pattern": "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}", "description": "ISO时间戳"},
			{"pattern": "csrf.?token|nonce|_token", "description": "CSRF/Nonce令牌"},
			{"pattern": "session.?id|jsessionid|phpsessid", "description": "会话ID"},
			{"pattern": "timestamp=\\d+", "description": "Unix时间戳参数"},
		},
		"dynamic_selectors": []map[string]string{
			{"selector": ".ad-container", "description": "广告容器"},
			{"selector": ".analytics", "description": "统计代码"},
			{"selector": "#live-chat", "description": "在线客服"},
			{"selector": ".countdown-timer", "description": "倒计时"},
		},
		"trusted_domains": []map[string]string{
			{"domain": "cdn.jsdelivr.net", "mark": "CDN"},
			{"domain": "cdnjs.cloudflare.com", "mark": "CDN"},
			{"domain": "unpkg.com", "mark": "CDN"},
			{"domain": "fonts.googleapis.com", "mark": "Google Fonts"},
			{"domain": "hm.baidu.com", "mark": "百度统计"},
		},
	},
	"blacklink": {
		"rules": []map[string]string{
			{"re": "(?i)(casino|gambling|bet365|poker)", "mark": "赌博"},
			{"re": "(?i)(porn|adult|xxx|sex)", "mark": "色情"},
			{"re": "(?i)(loan|credit.?card|payday)", "mark": "非法贷款"},
			{"re": "(?i)(pharmacy|viagra|cialis)", "mark": "非法药品"},
			{"re": "(?i)(fake.?(id|passport|diploma))", "mark": "假证件"},
		},
		"industry_blackwords": []map[string]string{
			{"re": "(?i)(赌博|博彩|棋牌|六合彩)", "mark": "赌博类"},
			{"re": "(?i)(色情|成人|裸聊)", "mark": "色情类"},
			{"re": "(?i)(代开发票|套现|洗钱)", "mark": "金融违规"},
		},
		"encoded_href_patterns": []map[string]string{
			{"re": "&#x[0-9a-fA-F]+;", "mark": "HTML实体编码"},
			{"re": "%[0-9a-fA-F]{2}", "mark": "URL编码"},
			{"re": "\\\\u[0-9a-fA-F]{4}", "mark": "Unicode编码"},
		},
		"backdoor_code_rules": []map[string]string{
			{"re": "(?i)(eval|assert|preg_replace.*e)\\s*\\(", "mark": "PHP后门"},
			{"re": "(?i)(base64_decode|gzinflate|gzuncompress|str_rot13)", "mark": "编码混淆"},
			{"re": "(?i)(cmd\\.exe|/bin/(ba)?sh|powershell)", "mark": "命令执行"},
			{"re": "(?i)(WScript\\.Shell|CreateObject)", "mark": "ASP后门"},
			{"re": "(?i)(Runtime\\.getRuntime\\(\\)\\.exec)", "mark": "Java后门"},
		},
		"backdoor_paths": []map[string]string{
			{"path": "/shell.php", "mark": "PHP WebShell", "risk": "critical"},
			{"path": "/cmd.asp", "mark": "ASP WebShell", "risk": "critical"},
			{"path": "/backdoor.jsp", "mark": "JSP后门", "risk": "critical"},
			{"path": "/.bash_history", "mark": "命令历史", "risk": "high"},
			{"path": "/debug.cgi", "mark": "调试CGI", "risk": "high"},
			{"path": "/test.php", "mark": "测试文件", "risk": "medium"},
			{"path": "/info.php", "mark": "phpinfo", "risk": "medium"},
			{"path": "/phpinfo.php", "mark": "phpinfo", "risk": "high"},
			{"path": "/.DS_Store", "mark": "macOS索引", "risk": "low"},
			{"path": "/Thumbs.db", "mark": "Windows缩略图", "risk": "low"},
		},
	},
	"sf_engine": {
		"content_patterns": []map[string]string{
			{"pattern": "(?i)(root:[x*]:0:0|\\[mysqld\\]|DB_PASSWORD)", "name": "配置文件泄露", "severity": "critical"},
			{"pattern": "(?i)(BEGIN (RSA |DSA |EC )?PRIVATE KEY)", "name": "私钥泄露", "severity": "critical"},
			{"pattern": "(?i)(password|passwd|secret)\\s*[:=]", "name": "密码泄露", "severity": "high"},
			{"pattern": "(?i)(api.?key|access.?token|secret.?key)\\s*[:=]", "name": "密钥泄露", "severity": "high"},
		},
		"soft_404_patterns": []map[string]string{
			{"pattern": "(?i)(page not found|404|not exist)", "description": "标准404"},
			{"pattern": "(?i)(error|oops|sorry)", "description": "错误页面"},
		},
		"backup_variants": []map[string]string{
			{"suffix": ".bak", "description": "备份文件"},
			{"suffix": ".old", "description": "旧版本文件"},
			{"suffix": ".swp", "description": "Vim交换文件"},
			{"suffix": ".save", "description": "保存文件"},
			{"suffix": "~", "description": "编辑器备份"},
			{"suffix": ".orig", "description": "原始文件"},
			{"suffix": ".copy", "description": "复制文件"},
			{"suffix": ".tar.gz", "description": "压缩包"},
			{"suffix": ".zip", "description": "ZIP压缩包"},
		},
		"high_risk_dirs": []map[string]string{
			{"path": "/.git/", "description": "Git仓库"},
			{"path": "/.svn/", "description": "SVN仓库"},
			{"path": "/wp-admin/", "description": "WordPress后台"},
			{"path": "/admin/", "description": "管理后台"},
			{"path": "/phpmyadmin/", "description": "phpMyAdmin"},
			{"path": "/.env", "description": "环境变量文件"},
			{"path": "/web.config", "description": "IIS配置"},
			{"path": "/server-status", "description": "Apache状态"},
		},
		"safe_files": []map[string]string{
			{"name": "robots.txt", "description": "爬虫协议"},
			{"name": "favicon.ico", "description": "网站图标"},
			{"name": "sitemap.xml", "description": "站点地图"},
			{"name": "crossdomain.xml", "description": "Flash跨域"},
		},
	},
	"sw_engine": {
		"violativelink_rules": []map[string]string{
			{"re": "(?i)(bit\\.ly|tinyurl|t\\.co|goo\\.gl)/[a-zA-Z0-9]+", "mark": "短链接"},
			{"re": "(?i)(onclick|onerror|onload)\\s*=", "mark": "事件注入"},
		},
	},
	"malware": {
		"js_malicious_patterns": []map[string]string{
			{"pattern": "(?i)(document\\.write\\s*\\(\\s*unescape)", "name": "写入反转义", "description": "疑似恶意代码注入", "severity": "high"},
			{"pattern": "(?i)(eval\\s*\\(\\s*(atob|decodeURI|unescape))", "name": "动态执行", "description": "动态解码并执行代码", "severity": "high"},
		},
		"miner_patterns": []map[string]string{
			{"pattern": "(?i)(coinhive|cryptonight|coinimp|minero|jsecoin)", "name": "挖矿脚本", "description": "已知挖矿库", "severity": "critical"},
			{"pattern": "(?i)(webassembly.*instantiate.*mining)", "name": "WASM挖矿", "description": "WebAssembly挖矿", "severity": "critical"},
		},
		"redirect_patterns": []map[string]string{
			{"pattern": "(?i)(window\\.location\\s*=\\s*['\"]https?://(?!\\w+\\.example\\.com))", "name": "JS重定向", "description": "JavaScript跳转到外部站点", "severity": "high"},
			{"pattern": "(?i)(meta.*http-equiv.*refresh.*url=)", "name": "Meta刷新", "description": "Meta标签跳转", "severity": "medium"},
		},
		"webshell_patterns": []map[string]string{
			{"pattern": "(?i)(c99shell|r57shell|b374k|weevely)", "name": "已知WebShell", "description": "匹配已知WebShell名称", "severity": "critical"},
		},
		"fetch_patterns": []map[string]string{
			{"pattern": "(?i)(fetch\\s*\\(\\s*['\"]https?://(?!\\w+\\.example\\.com))", "name": "外部Fetch", "description": "向外部域名发送Fetch请求", "severity": "medium"},
		},
		"malicious_domains_miner":        []map[string]string{{"domain": "coinhive.com"}, {"domain": "coin-hive.com"}, {"domain": "jsecoin.com"}, {"domain": "crypto-loot.com"}},
		"malicious_domains_c2":           []map[string]string{},
		"malicious_domains_phishing":     []map[string]string{},
		"malicious_domains_malvertising": []map[string]string{},
		"malicious_domains_seo_spam":     []map[string]string{},
		"malicious_domains_generic":      []map[string]string{},
	},
	"whiteip": {
		"entries": []map[string]string{
			{"domain": "127.0.0.1", "mark": "本地回环"},
			{"domain": "::1", "mark": "IPv6本地回环"},
		},
	},
}
