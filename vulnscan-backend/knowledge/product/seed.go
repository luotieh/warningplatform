package product

import (
	"log/slog"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type seedProduct struct {
	Name        string
	Vendor      string
	Category    string
	Description string
	Homepage    string
	CPEPrefix   string
	Aliases     []string
}

var builtinProducts = []seedProduct{
	{Name: "nginx", Vendor: "F5", Category: "web-server",
		Description: "Nginx 是一款高性能的 HTTP 和反向代理服务器，广泛用于网站托管、负载均衡和 API 网关场景。其事件驱动架构使其在高并发下仍保持低资源占用。",
		Homepage:    "https://nginx.org", CPEPrefix: "cpe:2.3:a:f5:nginx",
		Aliases: []string{"openresty", "tengine"}},
	{Name: "apache httpd", Vendor: "Apache Software Foundation", Category: "web-server",
		Description: "Apache HTTP Server 是世界上使用最广泛的 Web 服务器之一，支持模块化架构、虚拟主机、URL 重写等丰富功能。",
		Homepage:    "https://httpd.apache.org", CPEPrefix: "cpe:2.3:a:apache:http_server",
		Aliases: []string{"apache", "httpd"}},
	{Name: "iis", Vendor: "Microsoft", Category: "web-server",
		Description: "Internet Information Services (IIS) 是微软 Windows 平台上的 Web 服务器，支持 ASP.NET、PHP 等多种运行时，深度集成 Windows 身份认证。",
		Homepage:    "https://www.iis.net", CPEPrefix: "cpe:2.3:a:microsoft:internet_information_services",
		Aliases: []string{"microsoft-iis"}},
	{Name: "tomcat", Vendor: "Apache Software Foundation", Category: "web-server",
		Description: "Apache Tomcat 是一个开源的 Java Servlet 容器和 Web 服务器，是部署 Java Web 应用的事实标准之一。",
		Homepage:    "https://tomcat.apache.org", CPEPrefix: "cpe:2.3:a:apache:tomcat",
		Aliases: []string{"apache tomcat"}},
	{Name: "wordpress", Vendor: "WordPress Foundation", Category: "cms",
		Description: "WordPress 是全球使用量最大的内容管理系统 (CMS)，基于 PHP + MySQL 构建，拥有庞大的插件和主题生态。其广泛部署使其成为攻击者的重点目标。",
		Homepage:    "https://wordpress.org", CPEPrefix: "cpe:2.3:a:wordpress:wordpress",
		Aliases: []string{"wp"}},
	{Name: "spring boot", Vendor: "VMware", Category: "framework",
		Description: "Spring Boot 是基于 Spring 框架的快速开发框架，简化了 Java 企业应用的配置和部署。Actuator 端点暴露是常见安全风险。",
		Homepage:    "https://spring.io/projects/spring-boot", CPEPrefix: "cpe:2.3:a:vmware:spring_boot",
		Aliases: []string{"springboot", "spring-boot"}},
	{Name: "spring framework", Vendor: "VMware", Category: "framework",
		Description: "Spring Framework 是 Java 企业级应用开发的核心框架，提供依赖注入、AOP、事务管理等能力。Spring4Shell (CVE-2022-22965) 等漏洞影响广泛。",
		Homepage:    "https://spring.io/projects/spring-framework", CPEPrefix: "cpe:2.3:a:vmware:spring_framework",
		Aliases: []string{"spring"}},
	{Name: "php", Vendor: "The PHP Group", Category: "language",
		Description: "PHP 是一种广泛使用的服务端脚本语言，特别适用于 Web 开发。大量 CMS 和框架（WordPress、Laravel）基于 PHP 构建。",
		Homepage:    "https://www.php.net", CPEPrefix: "cpe:2.3:a:php:php"},
	{Name: "mysql", Vendor: "Oracle", Category: "database",
		Description: "MySQL 是全球最流行的开源关系型数据库，被广泛应用于 Web 后端数据存储。未授权访问和弱口令是常见风险。",
		Homepage:    "https://www.mysql.com", CPEPrefix: "cpe:2.3:a:oracle:mysql",
		Aliases: []string{"mariadb"}},
	{Name: "redis", Vendor: "Redis Ltd.", Category: "database",
		Description: "Redis 是高性能的内存键值数据库，常用于缓存、会话存储和消息队列。默认配置无认证是常见安全风险。",
		Homepage:    "https://redis.io", CPEPrefix: "cpe:2.3:a:redis:redis"},
	{Name: "elasticsearch", Vendor: "Elastic", Category: "database",
		Description: "Elasticsearch 是基于 Lucene 的分布式搜索和分析引擎，广泛用于日志分析和全文搜索。未授权 REST API 访问是常见风险。",
		Homepage:    "https://www.elastic.co/elasticsearch", CPEPrefix: "cpe:2.3:a:elastic:elasticsearch"},
	{Name: "jenkins", Vendor: "Jenkins", Category: "ci-cd",
		Description: "Jenkins 是最流行的开源持续集成/持续交付 (CI/CD) 服务器。其插件生态庞大，但历史上暴露了大量远程代码执行漏洞。",
		Homepage:    "https://www.jenkins.io", CPEPrefix: "cpe:2.3:a:jenkins:jenkins"},
	{Name: "grafana", Vendor: "Grafana Labs", Category: "monitor",
		Description: "Grafana 是一个开源的数据可视化和监控平台，支持多种数据源。路径穿越和未授权访问是其历史上的典型漏洞类型。",
		Homepage:    "https://grafana.com", CPEPrefix: "cpe:2.3:a:grafana:grafana"},
	{Name: "nacos", Vendor: "Alibaba", Category: "microservice",
		Description: "Nacos 是阿里巴巴开源的服务发现和配置管理平台，常见于微服务架构。默认身份绕过和敏感配置泄露是主要安全关注点。",
		Homepage:    "https://nacos.io", CPEPrefix: "cpe:2.3:a:alibaba:nacos"},
	{Name: "docker", Vendor: "Docker Inc.", Category: "container",
		Description: "Docker 是容器化技术的事实标准，简化了应用的打包、分发和运行。Docker API 未授权访问可直接导致主机沦陷。",
		Homepage:    "https://www.docker.com", CPEPrefix: "cpe:2.3:a:docker:docker"},
	{Name: "gitlab", Vendor: "GitLab Inc.", Category: "ci-cd",
		Description: "GitLab 是一站式 DevOps 平台，提供代码仓库、CI/CD 流水线和安全扫描能力。历史上多次出现 SSRF 和 RCE 漏洞。",
		Homepage:    "https://about.gitlab.com", CPEPrefix: "cpe:2.3:a:gitlab:gitlab"},
	{Name: "jquery", Vendor: "jQuery Foundation", Category: "js-library",
		Description: "jQuery 是最经典的 JavaScript 工具库，简化了 DOM 操作和 Ajax 调用。老版本存在多个 XSS 漏洞。",
		Homepage:    "https://jquery.com", CPEPrefix: "cpe:2.3:a:jquery:jquery"},
	{Name: "vue.js", Vendor: "Evan You", Category: "js-framework",
		Description: "Vue.js 是一个渐进式 JavaScript 前端框架，以其简洁的 API 和优秀的文档著称，广泛应用于中国企业级应用。",
		Homepage:    "https://vuejs.org",
		Aliases:     []string{"vue", "vuejs"}},
	{Name: "react", Vendor: "Meta (Facebook)", Category: "js-framework",
		Description: "React 是 Meta 开源的声明式 JavaScript UI 库，采用组件化开发模式，是全球使用最广泛的前端框架之一。",
		Homepage:    "https://react.dev",
		Aliases:     []string{"reactjs", "next.js", "nextjs"}},
	{Name: "weblogic", Vendor: "Oracle", Category: "web-server",
		Description: "Oracle WebLogic Server 是企业级 Java 应用服务器，常见于金融、电信等行业。其 T3/IIOP 协议反序列化漏洞影响极为广泛。",
		Homepage:    "https://www.oracle.com/middleware/technologies/weblogic.html", CPEPrefix: "cpe:2.3:a:oracle:weblogic_server"},
	{Name: "jboss", Vendor: "Red Hat", Category: "web-server",
		Description: "JBoss (WildFly) 是 Red Hat 开源的 Java 应用服务器。JMX Console 和 JBossWeb 的历史漏洞是渗透测试中的经典案例。",
		Homepage:    "https://www.wildfly.org", CPEPrefix: "cpe:2.3:a:redhat:jboss_enterprise_application_platform",
		Aliases: []string{"wildfly"}},
	{Name: "shiro", Vendor: "Apache Software Foundation", Category: "framework",
		Description: "Apache Shiro 是一个 Java 安全框架，提供认证、授权、会话管理能力。Shiro 反序列化漏洞 (CVE-2016-4437) 是经典高危漏洞。",
		Homepage:    "https://shiro.apache.org", CPEPrefix: "cpe:2.3:a:apache:shiro",
		Aliases: []string{"apache shiro"}},
	{Name: "thinkphp", Vendor: "TopThink", Category: "framework",
		Description: "ThinkPHP 是国内广泛使用的 PHP 快速开发框架。多个版本存在远程代码执行漏洞，在中国互联网环境中是高频攻击目标。",
		Homepage:    "https://www.thinkphp.cn"},
	{Name: "fastjson", Vendor: "Alibaba", Category: "framework",
		Description: "Fastjson 是阿里巴巴开源的高性能 Java JSON 解析库。其 AutoType 特性导致了多轮反序列化 RCE 漏洞，影响大量 Java 应用。",
		Homepage:    "https://github.com/alibaba/fastjson", CPEPrefix: "cpe:2.3:a:alibaba:fastjson"},
	{Name: "openssh", Vendor: "OpenBSD", Category: "other",
		Description: "OpenSSH 是最广泛使用的 SSH 协议实现，提供远程加密登录和文件传输能力。配置不当或旧版本漏洞可导致未授权访问。",
		Homepage:    "https://www.openssh.com", CPEPrefix: "cpe:2.3:a:openbsd:openssh"},
}

// SeedBuiltinProducts 初始化内置产品数据。
func SeedBuiltinProducts(session *gorm.DB) {
	created := 0
	for _, sp := range builtinProducts {
		var count int64
		session.Model(&model.Product{}).Where("name = ?", sp.Name).Count(&count)
		if count > 0 {
			continue
		}

		item := model.Product{
			Name:        sp.Name,
			Vendor:      sp.Vendor,
			Category:    sp.Category,
			Description: sp.Description,
			Homepage:    sp.Homepage,
			CPEPrefix:   sp.CPEPrefix,
			Aliases:     sp.Aliases,
		}
		item.ID = ulid.GenerateID()
		item.CreatedBy = "system"

		if err := session.Create(&item).Error; err != nil {
			slog.Debug("[ProductSeed] 创建内置产品失败", "name", sp.Name, "error", err)
			continue
		}
		created++
	}
	if created > 0 {
		slog.Info("[ProductSeed] 内置产品初始化完成", "created", created, "total", len(builtinProducts))
	}
}
