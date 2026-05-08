package setting

type settingDefault struct {
	Key         string
	Value       string
	Group       string
	Label       string
	Description string
	ValueType   string
	IsSecret    bool
}

func defaultSettings() []settingDefault {
	return []settingDefault{
		// 扫描引擎
		{Key: "scanner.mode", Value: "standalone", Group: "scanner", Label: "运行模式", Description: "standalone / central / sub-master", ValueType: "string"},
		{Key: "scanner.worker_pool_size", Value: "100", Group: "scanner", Label: "Worker池大小", Description: "扫描引擎工作线程池大小", ValueType: "int"},
		{Key: "scanner.max_concurrency", Value: "50", Group: "scanner", Label: "最大并发", Description: "单任务最大并发数", ValueType: "int"},
		{Key: "scanner.plugin_dir", Value: "./plugins", Group: "scanner", Label: "插件目录", ValueType: "string"},
		{Key: "scanner.template_dir", Value: "./templates", Group: "scanner", Label: "模板目录", ValueType: "string"},

		// 调度器
		{Key: "scheduler.enabled", Value: "true", Group: "scheduler", Label: "启用调度器", ValueType: "bool"},
		{Key: "scheduler.redis_queue", Value: "vs:task:queue", Group: "scheduler", Label: "Redis队列名", ValueType: "string"},
		{Key: "scheduler.poll_interval", Value: "1s", Group: "scheduler", Label: "轮询间隔", Description: "任务队列轮询间隔（如 1s, 500ms）", ValueType: "string"},
		{Key: "scheduler.max_retries", Value: "3", Group: "scheduler", Label: "最大重试", Description: "任务失败最大重试次数", ValueType: "int"},

		// 联邦
		{Key: "federation.enabled", Value: "false", Group: "federation", Label: "启用联邦", ValueType: "bool"},
		{Key: "federation.listen_addr", Value: ":9443", Group: "federation", Label: "监听地址", ValueType: "string"},
		{Key: "federation.tls_cert", Value: "", Group: "federation", Label: "TLS证书路径", ValueType: "string"},
		{Key: "federation.tls_key", Value: "", Group: "federation", Label: "TLS密钥路径", ValueType: "string", IsSecret: true},
		{Key: "federation.ca_cert", Value: "", Group: "federation", Label: "CA证书路径", ValueType: "string"},
		{Key: "federation.upstream.central_url", Value: "", Group: "federation", Label: "上级节点地址", ValueType: "string"},
		{Key: "federation.upstream.api_token", Value: "", Group: "federation", Label: "上级API Token", ValueType: "string", IsSecret: true},
		{Key: "federation.upstream.sync_interval", Value: "10m", Group: "federation", Label: "同步间隔", ValueType: "string"},
		{Key: "federation.upstream.report_interval", Value: "5m", Group: "federation", Label: "报告间隔", ValueType: "string"},
		{Key: "federation.upstream.offline_grace_days", Value: "30", Group: "federation", Label: "离线宽限天数", ValueType: "int"},

		// 网络空间测绘
		{Key: "cyberspace.fofa.api_key", Value: "", Group: "cyberspace", Label: "FOFA API Key", ValueType: "string", IsSecret: true},
		{Key: "cyberspace.fofa.base_url", Value: "https://fofa.info", Group: "cyberspace", Label: "FOFA 地址", ValueType: "string"},
		{Key: "cyberspace.fofa.enabled", Value: "false", Group: "cyberspace", Label: "启用 FOFA", ValueType: "bool"},
		{Key: "cyberspace.fofa.rate_limit", Value: "5", Group: "cyberspace", Label: "FOFA 速率限制", Description: "每秒最大请求数", ValueType: "int"},
		{Key: "cyberspace.hunter.api_key", Value: "", Group: "cyberspace", Label: "Hunter API Key", ValueType: "string", IsSecret: true},
		{Key: "cyberspace.hunter.base_url", Value: "https://hunter.qianxin.com", Group: "cyberspace", Label: "Hunter 地址", ValueType: "string"},
		{Key: "cyberspace.hunter.enabled", Value: "false", Group: "cyberspace", Label: "启用 Hunter", ValueType: "bool"},
		{Key: "cyberspace.hunter.rate_limit", Value: "5", Group: "cyberspace", Label: "Hunter 速率限制", ValueType: "int"},
		{Key: "cyberspace.shodan.api_key", Value: "", Group: "cyberspace", Label: "Shodan API Key", ValueType: "string", IsSecret: true},
		{Key: "cyberspace.shodan.base_url", Value: "https://api.shodan.io", Group: "cyberspace", Label: "Shodan 地址", ValueType: "string"},
		{Key: "cyberspace.shodan.enabled", Value: "false", Group: "cyberspace", Label: "启用 Shodan", ValueType: "bool"},
		{Key: "cyberspace.shodan.rate_limit", Value: "1", Group: "cyberspace", Label: "Shodan 速率限制", ValueType: "int"},
	}
}
