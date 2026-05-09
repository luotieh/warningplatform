package migration

import (
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func seedDefaultServiceFingerprints(db *gorm.DB) error {
	var count int64
	db.Model(&model.ServiceFingerprint{}).Count(&count)
	if count > 0 {
		return nil
	}

	fingerprints := []model.ServiceFingerprint{
		// ============================================================
		// 被动识别规则 (passive) — Banner 匹配
		// ============================================================

		// --- SSH ---
		{Name: "SSH-OpenSSH", Service: "SSH", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)`, VersionExpr: `([\d.p]+)`, Priority: 90, Ports: "22,2222", Status: model.FingerprintStatusActive, Source: "default", Description: "OpenSSH 服务识别"},
		{Name: "SSH-Dropbear", Service: "SSH", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^SSH-[\d.]+-dropbear[_\s]*([\d.]+)`, VersionExpr: `([\d.]+)`, Priority: 89, Ports: "22,2222", Status: model.FingerprintStatusActive, Source: "default", Description: "Dropbear SSH 服务识别"},
		{Name: "SSH-Generic", Service: "SSH", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^SSH-`, Priority: 80, Ports: "22,2222", Status: model.FingerprintStatusActive, Source: "default", Description: "通用 SSH 服务识别"},

		// --- FTP ---
		{Name: "FTP-vsftpd", Service: "FTP", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^220.*vsftpd\s*([\d.]+)`, VersionExpr: `([\d.]+)`, Priority: 90, Ports: "21", Status: model.FingerprintStatusActive, Source: "default", Description: "vsftpd 服务识别"},
		{Name: "FTP-ProFTPD", Service: "FTP", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^220.*ProFTPD\s*([\d.]+)`, VersionExpr: `([\d.]+)`, Priority: 90, Ports: "21", Status: model.FingerprintStatusActive, Source: "default", Description: "ProFTPD 服务识别"},
		{Name: "FTP-FileZilla", Service: "FTP", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^220.*FileZilla`, Priority: 85, Ports: "21", Status: model.FingerprintStatusActive, Source: "default", Description: "FileZilla FTP 服务识别"},

		// --- SMTP ---
		{Name: "SMTP-Postfix", Service: "SMTP", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^220.*Postfix`, Priority: 90, Ports: "25,465,587", Status: model.FingerprintStatusActive, Source: "default", Description: "Postfix SMTP 服务识别"},
		{Name: "SMTP-Exim", Service: "SMTP", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)^220.*Exim`, Priority: 90, Ports: "25,465,587", Status: model.FingerprintStatusActive, Source: "default", Description: "Exim SMTP 服务识别"},

		// --- 数据库 ---
		{Name: "Redis", Service: "Redis", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `-DENIED|-\w+\s+command`, Priority: 85, Ports: "6379", Status: model.FingerprintStatusActive, Source: "default", Description: "Redis 服务识别"},
		{Name: "MongoDB", Service: "MongoDB", ProbeType: model.ProbeTypePassive, MatchType: model.MatchTypeRegex, MatchRule: `(?i)mongodb|mongo`, Priority: 85, Ports: "27017", Status: model.FingerprintStatusActive, Source: "default", Description: "MongoDB 服务识别"},

		// ============================================================
		// 主动探测规则 (active) — 发送 Probe 后匹配响应
		// ============================================================

		// --- HTTP 探测 ---
		{Name: "Probe-HTTP", Service: "HTTP", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `^HTTP/[\d.]+ \d{3}`, Priority: 80, Ports: "80,8080,8000,8008,8888,8090,3000,5000,9090", Status: model.FingerprintStatusActive, Source: "default", Description: "HTTP 服务探测"},
		{Name: "Probe-HTTPS", Service: "HTTPS", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `^HTTP/[\d.]+ \d{3}`, Priority: 80, Ports: "443,8443", Status: model.FingerprintStatusActive, Source: "default", Description: "HTTPS 服务探测"},

		// --- 数据库 ---
		{Name: "Probe-Redis", Service: "Redis", ProbeType: model.ProbeTypeActive, ProbeData: "PING\r\n", MatchType: model.MatchTypeRegex, MatchRule: `\+PONG`, Priority: 90, Ports: "6379", Status: model.FingerprintStatusActive, Source: "default", Description: "Redis 主动探测"},
		{Name: "Probe-MySQL", Service: "MySQL", ProbeType: model.ProbeTypeActive, ProbeData: "", MatchType: model.MatchTypeRegex, MatchRule: `(?i)mysql|MariaDB`, Priority: 80, Ports: "3306", Status: model.FingerprintStatusActive, Source: "default", Description: "MySQL 主动探测"},
		{Name: "Probe-PostgreSQL", Service: "PostgreSQL", ProbeType: model.ProbeTypeActive, ProbeData: "", MatchType: model.MatchTypeRegex, MatchRule: `(?i)postgresql|postgres`, Priority: 80, Ports: "5432", Status: model.FingerprintStatusActive, Source: "default", Description: "PostgreSQL 主动探测"},
		{Name: "Probe-MongoDB", Service: "MongoDB", ProbeType: model.ProbeTypeActive, ProbeData: "", MatchType: model.MatchTypeRegex, MatchRule: `(?i)mongodb`, Priority: 80, Ports: "27017", Status: model.FingerprintStatusActive, Source: "default", Description: "MongoDB 主动探测"},
		{Name: "Probe-Elasticsearch", Service: "Elasticsearch", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `"cluster_name"`, Priority: 85, Ports: "9200", Status: model.FingerprintStatusActive, Source: "default", Description: "Elasticsearch 主动探测"},

		// --- 中间件/应用服务器 ---
		{Name: "Probe-Tomcat", Service: "Tomcat", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Apache Tomcat|tomcat`, Priority: 85, Ports: "8080,8443", Status: model.FingerprintStatusActive, Source: "default", Description: "Tomcat 主动探测"},
		{Name: "Probe-JBoss", Service: "JBoss", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)JBoss|jboss`, Priority: 85, Ports: "8080,8443", Status: model.FingerprintStatusActive, Source: "default", Description: "JBoss 主动探测"},
		{Name: "Probe-WebLogic", Service: "WebLogic", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)WebLogic|weblogic`, Priority: 85, Ports: "7001,7002", Status: model.FingerprintStatusActive, Source: "default", Description: "WebLogic 主动探测"},
		{Name: "Probe-WebSphere", Service: "WebSphere", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)WebSphere|websphere`, Priority: 85, Ports: "9080,9443", Status: model.FingerprintStatusActive, Source: "default", Description: "WebSphere 主动探测"},
		{Name: "Probe-Nginx", Service: "Nginx", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)nginx`, Priority: 85, Ports: "80,443,8080", Status: model.FingerprintStatusActive, Source: "default", Description: "Nginx 主动探测"},
		{Name: "Probe-Apache", Service: "Apache", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Apache`, Priority: 85, Ports: "80,443,8080", Status: model.FingerprintStatusActive, Source: "default", Description: "Apache HTTP Server 主动探测"},
		{Name: "Probe-IIS", Service: "IIS", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Microsoft-IIS`, Priority: 85, Ports: "80,443", Status: model.FingerprintStatusActive, Source: "default", Description: "IIS 主动探测"},

		// --- 分布式/服务注册 ---
		{Name: "Probe-Zookeeper", Service: "Zookeeper", ProbeType: model.ProbeTypeActive, ProbeData: "ruok", MatchType: model.MatchTypeRegex, MatchRule: `^imok`, Priority: 90, Ports: "2181", Status: model.FingerprintStatusActive, Source: "default", Description: "Zookeeper 主动探测"},
		{Name: "Probe-RabbitMQ", Service: "RabbitMQ", ProbeType: model.ProbeTypeActive, ProbeData: "GET /api/overview HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)rabbitmq|management_version`, Priority: 80, Ports: "15672", Status: model.FingerprintStatusActive, Source: "default", Description: "RabbitMQ 主动探测"},
		{Name: "Probe-Docker", Service: "Docker", ProbeType: model.ProbeTypeActive, ProbeData: "GET /version HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `"ApiVersion"`, Priority: 85, Ports: "2375,2376", Status: model.FingerprintStatusActive, Source: "default", Description: "Docker API 主动探测"},
		{Name: "Probe-K8s", Service: "Kubernetes", ProbeType: model.ProbeTypeActive, ProbeData: "GET /version HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `"gitVersion"`, Priority: 85, Ports: "6443", Status: model.FingerprintStatusActive, Source: "default", Description: "Kubernetes API 主动探测"},
		{Name: "Probe-Consul", Service: "Consul", ProbeType: model.ProbeTypeActive, ProbeData: "GET /v1/agent/self HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"Config".*"Datacenter"`, Priority: 80, Ports: "8500", Status: model.FingerprintStatusActive, Source: "default", Description: "Consul 主动探测"},
		{Name: "Probe-Etcd", Service: "etcd", ProbeType: model.ProbeTypeActive, ProbeData: "GET /version HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `"etcdserver"`, Priority: 85, Ports: "2379", Status: model.FingerprintStatusActive, Source: "default", Description: "etcd 主动探测"},
		{Name: "Probe-Prometheus", Service: "Prometheus", ProbeType: model.ProbeTypeActive, ProbeData: "GET /api/v1/status/buildinfo HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `"goVersion"`, Priority: 80, Ports: "9090", Status: model.FingerprintStatusActive, Source: "default", Description: "Prometheus 主动探测"},
		{Name: "Probe-Grafana", Service: "Grafana", ProbeType: model.ProbeTypeActive, ProbeData: "GET /api/health HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"database"\s*:\s*"ok"`, Priority: 80, Ports: "3000", Status: model.FingerprintStatusActive, Source: "default", Description: "Grafana 主动探测"},
		{Name: "Probe-Nacos", Service: "Nacos", ProbeType: model.ProbeTypeActive, ProbeData: "GET /nacos/ HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)nacos`, Priority: 80, Ports: "8848", Status: model.FingerprintStatusActive, Source: "default", Description: "Nacos 主动探测"},
		{Name: "Probe-Vault", Service: "Vault", ProbeType: model.ProbeTypeActive, ProbeData: "GET /v1/sys/health HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"initialized"`, Priority: 80, Ports: "8200", Status: model.FingerprintStatusActive, Source: "default", Description: "HashiCorp Vault 主动探测"},

		// --- CI/CD / DevOps ---
		{Name: "Probe-Jenkins", Service: "Jenkins", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)X-Jenkins`, Priority: 85, Ports: "8080", Status: model.FingerprintStatusActive, Source: "default", Description: "Jenkins 主动探测"},
		{Name: "Probe-GitLab", Service: "GitLab", ProbeType: model.ProbeTypeActive, ProbeData: "GET /api/v4/version HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"version"`, Priority: 78, Ports: "80,443,8080", Status: model.FingerprintStatusActive, Source: "default", Description: "GitLab 主动探测"},
		{Name: "Probe-SonarQube", Service: "SonarQube", ProbeType: model.ProbeTypeActive, ProbeData: "GET /api/system/status HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"status"`, Priority: 78, Ports: "9000", Status: model.FingerprintStatusActive, Source: "default", Description: "SonarQube 主动探测"},
		{Name: "Probe-MinIO", Service: "MinIO", ProbeType: model.ProbeTypeActive, ProbeData: "GET /minio/health/live HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `HTTP/[\d.]+ 200`, Priority: 80, Ports: "9000", Status: model.FingerprintStatusActive, Source: "default", Description: "MinIO 主动探测"},
		{Name: "Probe-Kibana", Service: "Kibana", ProbeType: model.ProbeTypeActive, ProbeData: "GET /api/status HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)kibana`, Priority: 80, Ports: "5601", Status: model.FingerprintStatusActive, Source: "default", Description: "Kibana 主动探测"},

		// --- 其他服务 ---
		{Name: "Probe-Rsync", Service: "Rsync", ProbeType: model.ProbeTypeActive, ProbeData: "", MatchType: model.MatchTypeRegex, MatchRule: `^@RSYNCD`, Priority: 85, Ports: "873", Status: model.FingerprintStatusActive, Source: "default", Description: "Rsync 主动探测"},
		{Name: "Probe-Socks5", Service: "SOCKS5", ProbeType: model.ProbeTypeActive, ProbeData: "\x05\x01\x00", MatchType: model.MatchTypeHex, MatchRule: `^\x05[\x00\xff]`, Priority: 80, Ports: "1080", Status: model.FingerprintStatusActive, Source: "default", Description: "SOCKS5 代理主动探测"},
		{Name: "Probe-Zabbix", Service: "Zabbix", ProbeType: model.ProbeTypeActive, ProbeData: "", MatchType: model.MatchTypeRegex, MatchRule: `(?i)ZBXD`, Priority: 78, Ports: "10050,10051", Status: model.FingerprintStatusActive, Source: "default", Description: "Zabbix 主动探测"},

		// ============================================================
		// HTTP 深度识别规则（多路径探测）
		// ============================================================
		{Name: "HTTP-Deep-Spring", Service: "Spring Boot", ProbeType: model.ProbeTypeActive, ProbeData: "GET /actuator/env HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"activeProfiles"`, Priority: 92, Ports: "8080,80,443", HTTPPaths: "/actuator/env,/actuator/health", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Spring Boot Actuator 深度识别"},
		{Name: "HTTP-Deep-Django", Service: "Django", ProbeType: model.ProbeTypeActive, ProbeData: "GET /admin/ HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)django|Django administration`, Priority: 90, Ports: "8000,80,443", HTTPPaths: "/admin/,/admin/login/", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Django Admin 深度识别"},
		{Name: "HTTP-Deep-WordPress", Service: "WordPress", ProbeType: model.ProbeTypeActive, ProbeData: "GET /wp-login.php HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)WordPress|wp-login`, Priority: 92, Ports: "80,443", HTTPPaths: "/wp-login.php,/wp-admin/,/wp-content/", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "WordPress 深度识别"},
		{Name: "HTTP-Deep-Jenkins", Service: "Jenkins", ProbeType: model.ProbeTypeActive, ProbeData: "GET /login HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)X-Jenkins|Jenkins`, Priority: 90, Ports: "8080,80,443", HTTPPaths: "/login,/manage", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Jenkins 深度识别"},
		{Name: "HTTP-Deep-Grafana", Service: "Grafana", ProbeType: model.ProbeTypeActive, ProbeData: "GET /login HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Grafana|grafana`, Priority: 90, Ports: "3000,80,443", HTTPPaths: "/login,/api/health", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Grafana 深度识别"},
		{Name: "HTTP-Deep-Kibana", Service: "Kibana", ProbeType: model.ProbeTypeActive, ProbeData: "GET /app/kibana HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Kibana|kibana`, Priority: 90, Ports: "5601,80,443", HTTPPaths: "/app/kibana,/api/status", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Kibana 深度识别"},
		{Name: "HTTP-Deep-Nacos", Service: "Nacos", ProbeType: model.ProbeTypeActive, ProbeData: "GET /nacos/ HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Nacos|nacos`, Priority: 90, Ports: "8848,80,443", HTTPPaths: "/nacos/,/nacos/v1/cs/health", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Nacos 深度识别"},
		{Name: "HTTP-Deep-Swagger", Service: "Swagger UI", ProbeType: model.ProbeTypeActive, ProbeData: "GET /swagger-ui.html HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)swagger|Swagger UI`, Priority: 88, Ports: "8080,80,443", HTTPPaths: "/swagger-ui.html,/swagger/index.html,/api-docs", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Swagger UI 深度识别"},
		{Name: "HTTP-Deep-Prometheus", Service: "Prometheus", ProbeType: model.ProbeTypeActive, ProbeData: "GET /graph HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)Prometheus|prometheus`, Priority: 88, Ports: "9090,80,443", HTTPPaths: "/graph,/api/v1/status/buildinfo", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Prometheus 深度识别"},
		{Name: "HTTP-Deep-Elasticsearch", Service: "Elasticsearch", ProbeType: model.ProbeTypeActive, ProbeData: "GET / HTTP/1.0\r\nHost: probe\r\n\r\n", MatchType: model.MatchTypeRegex, MatchRule: `(?i)"cluster_name"|"tagline"`, Priority: 90, Ports: "9200,80,443", HTTPPaths: "/,/_cluster/health", HTTPMethod: "GET", Status: model.FingerprintStatusActive, Source: "default", Description: "Elasticsearch 深度识别"},

		// ============================================================
		// TLS 证书分析规则
		// ============================================================
		{Name: "TLS-SelfSigned", Service: "HTTPS", ProbeType: model.ProbeTypeActive, MatchType: model.MatchTypeTLS, MatchRule: "self_signed", Priority: 70, Ports: "443,8443", TLSMatchCN: true, TLSMatchSelfSign: true, Status: model.FingerprintStatusActive, Source: "default", Description: "自签名 TLS 证书识别"},
		{Name: "TLS-LetsEncrypt", Service: "HTTPS", ProbeType: model.ProbeTypeActive, MatchType: model.MatchTypeTLS, MatchRule: "lets_encrypt", Priority: 75, Ports: "443,8443", TLSMatchIssuer: true, Status: model.FingerprintStatusActive, Source: "default", Description: "Let's Encrypt 证书识别"},
	}

	for _, fp := range fingerprints {
		if fp.SourceType == "" {
			fp.SourceType = "local"
		}
		if err := db.Create(&fp).Error; err != nil {
			return err
		}
	}

	// 种子端口-服务映射
	portMaps := []model.PortServiceMap{
		{Port: 20, Protocol: "tcp", Service: "FTP-Data", Status: model.FingerprintStatusActive},
		{Port: 21, Protocol: "tcp", Service: "FTP", Status: model.FingerprintStatusActive},
		{Port: 22, Protocol: "tcp", Service: "SSH", Status: model.FingerprintStatusActive},
		{Port: 23, Protocol: "tcp", Service: "Telnet", Status: model.FingerprintStatusActive},
		{Port: 25, Protocol: "tcp", Service: "SMTP", Status: model.FingerprintStatusActive},
		{Port: 53, Protocol: "tcp", Service: "DNS", Status: model.FingerprintStatusActive},
		{Port: 80, Protocol: "tcp", Service: "HTTP", Status: model.FingerprintStatusActive},
		{Port: 110, Protocol: "tcp", Service: "POP3", Status: model.FingerprintStatusActive},
		{Port: 143, Protocol: "tcp", Service: "IMAP", Status: model.FingerprintStatusActive},
		{Port: 443, Protocol: "tcp", Service: "HTTPS", Status: model.FingerprintStatusActive},
		{Port: 445, Protocol: "tcp", Service: "SMB", Status: model.FingerprintStatusActive},
		{Port: 993, Protocol: "tcp", Service: "IMAPS", Status: model.FingerprintStatusActive},
		{Port: 995, Protocol: "tcp", Service: "POP3S", Status: model.FingerprintStatusActive},
		{Port: 1433, Protocol: "tcp", Service: "MSSQL", Status: model.FingerprintStatusActive},
		{Port: 1521, Protocol: "tcp", Service: "Oracle", Status: model.FingerprintStatusActive},
		{Port: 3306, Protocol: "tcp", Service: "MySQL", Status: model.FingerprintStatusActive},
		{Port: 3389, Protocol: "tcp", Service: "RDP", Status: model.FingerprintStatusActive},
		{Port: 5432, Protocol: "tcp", Service: "PostgreSQL", Status: model.FingerprintStatusActive},
		{Port: 5900, Protocol: "tcp", Service: "VNC", Status: model.FingerprintStatusActive},
		{Port: 6379, Protocol: "tcp", Service: "Redis", Status: model.FingerprintStatusActive},
		{Port: 8080, Protocol: "tcp", Service: "HTTP-Proxy", Status: model.FingerprintStatusActive},
		{Port: 8443, Protocol: "tcp", Service: "HTTPS-Alt", Status: model.FingerprintStatusActive},
		{Port: 9200, Protocol: "tcp", Service: "Elasticsearch", Status: model.FingerprintStatusActive},
		{Port: 27017, Protocol: "tcp", Service: "MongoDB", Status: model.FingerprintStatusActive},
	}

	for _, pm := range portMaps {
		if err := db.Create(&pm).Error; err != nil {
			return err
		}
	}

	return nil
}
