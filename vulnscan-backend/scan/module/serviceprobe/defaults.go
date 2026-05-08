package serviceprobe

type defaultFP struct {
	name        string
	service     string
	probeType   string
	probeData   string
	matchRegex  string
	versionExpr string
	ports       string
	priority    int
}

func defaultFingerprints() []defaultFP {
	return []defaultFP{
		// ============================================================
		// 被动识别规则 (passive) — Banner 匹配
		// ============================================================

		// --- SSH ---
		{name: "SSH-OpenSSH", service: "SSH", probeType: "passive", matchRegex: `(?i)^SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)`, priority: 90, ports: "22,2222"},
		{name: "SSH-Dropbear", service: "SSH", probeType: "passive", matchRegex: `(?i)^SSH-[\d.]+-dropbear[_\s]*([\d.]+)`, priority: 89, ports: "22,2222"},
		{name: "SSH-libssh", service: "SSH", probeType: "passive", matchRegex: `(?i)^SSH-[\d.]+-libssh[_\s]*([\d.]+)`, priority: 88, ports: "22"},
		{name: "SSH-Paramiko", service: "SSH", probeType: "passive", matchRegex: `(?i)^SSH-[\d.]+-paramiko`, priority: 87, ports: "22"},
		{name: "SSH-Bitvise", service: "SSH", probeType: "passive", matchRegex: `(?i)^SSH-[\d.]+-FlowSsh`, priority: 86, ports: "22"},
		{name: "SSH-Cisco", service: "SSH", probeType: "passive", matchRegex: `(?i)^SSH-[\d.]+-Cisco`, priority: 86, ports: "22"},
		{name: "SSH-Generic", service: "SSH", probeType: "passive", matchRegex: `^SSH-[\d.]+-`, priority: 70, ports: "22,2222"},

		// --- FTP ---
		{name: "FTP-vsftpd", service: "FTP", probeType: "passive", matchRegex: `(?i)^220.*vsftpd\s*([\d.]+)`, priority: 90, ports: "21"},
		{name: "FTP-ProFTPD", service: "FTP", probeType: "passive", matchRegex: `(?i)^220.*ProFTPD\s*([\d.]+)`, priority: 89, ports: "21"},
		{name: "FTP-PureFTPd", service: "FTP", probeType: "passive", matchRegex: `(?i)^220.*Pure-FTPd`, priority: 88, ports: "21"},
		{name: "FTP-FileZilla", service: "FTP", probeType: "passive", matchRegex: `(?i)^220.*FileZilla\s+Server\s*([\d.]+)`, priority: 88, ports: "21"},
		{name: "FTP-WuFTP", service: "FTP", probeType: "passive", matchRegex: `(?i)^220.*wu-[\d.]+ FTP`, priority: 87, ports: "21"},
		{name: "FTP-MicrosoftFTP", service: "FTP", probeType: "passive", matchRegex: `(?i)^220.*Microsoft FTP Service`, priority: 88, ports: "21"},
		{name: "FTP-Generic", service: "FTP", probeType: "passive", matchRegex: `^220[\s-].*(?i:FTP)`, priority: 60, ports: "21"},

		// --- SMTP ---
		{name: "SMTP-Postfix", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*Postfix`, priority: 90, ports: "25,465,587"},
		{name: "SMTP-Sendmail", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*Sendmail\s*([\d.]+)`, priority: 89, ports: "25"},
		{name: "SMTP-Exchange", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*Microsoft ESMTP`, priority: 89, ports: "25,587"},
		{name: "SMTP-Exim", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*Exim\s*([\d.]+)`, priority: 88, ports: "25,587"},
		{name: "SMTP-Haraka", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*Haraka`, priority: 87, ports: "25"},
		{name: "SMTP-Zimbra", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*Zimbra`, priority: 87, ports: "25,587"},
		{name: "SMTP-hMailServer", service: "SMTP", probeType: "passive", matchRegex: `(?i)^220.*hMailServer`, priority: 86, ports: "25,587"},
		{name: "SMTP-Generic", service: "SMTP", probeType: "passive", matchRegex: `^220[\s-].*(?i:SMTP|ESMTP)`, priority: 60, ports: "25,465,587"},

		// --- HTTP Server ---
		{name: "HTTP-Response", service: "HTTP", probeType: "passive", matchRegex: `^HTTP/[\d.]+ \d{3}`, priority: 85},
		{name: "HTTP-Nginx", service: "Nginx", probeType: "passive", matchRegex: `(?i)Server:\s*nginx[/ ]*([\d.]+)?`, versionExpr: `nginx[/ ]*([\d.]+)`, priority: 90},
		{name: "HTTP-Apache", service: "Apache", probeType: "passive", matchRegex: `(?i)Server:\s*Apache[/ ]*([\d.]+)?`, versionExpr: `Apache[/ ]*([\d.]+)`, priority: 90},
		{name: "HTTP-IIS", service: "IIS", probeType: "passive", matchRegex: `(?i)Server:\s*Microsoft-IIS/([\d.]+)`, priority: 90},
		{name: "HTTP-Tomcat", service: "Tomcat", probeType: "passive", matchRegex: `(?i)Server:\s*Apache-Coyote/([\d.]+)`, priority: 89},
		{name: "HTTP-LiteSpeed", service: "LiteSpeed", probeType: "passive", matchRegex: `(?i)Server:\s*LiteSpeed`, priority: 88},
		{name: "HTTP-Caddy", service: "Caddy", probeType: "passive", matchRegex: `(?i)Server:\s*Caddy`, priority: 88},
		{name: "HTTP-Jetty", service: "Jetty", probeType: "passive", matchRegex: `(?i)Server:\s*Jetty\(([\d.]+)`, priority: 87},
		{name: "HTTP-Openresty", service: "OpenResty", probeType: "passive", matchRegex: `(?i)Server:\s*openresty[/ ]*([\d.]+)?`, priority: 89},
		{name: "HTTP-Tengine", service: "Tengine", probeType: "passive", matchRegex: `(?i)Server:\s*Tengine[/ ]*([\d.]+)?`, versionExpr: `Tengine[/ ]*([\d.]+)`, priority: 89},
		{name: "HTTP-Cowboy", service: "Cowboy", probeType: "passive", matchRegex: `(?i)Server:\s*Cowboy`, priority: 86},
		{name: "HTTP-Gunicorn", service: "Gunicorn", probeType: "passive", matchRegex: `(?i)Server:\s*gunicorn[/ ]*([\d.]+)?`, versionExpr: `gunicorn[/ ]*([\d.]+)`, priority: 87},
		{name: "HTTP-Uvicorn", service: "Uvicorn", probeType: "passive", matchRegex: `(?i)Server:\s*uvicorn`, priority: 86},
		{name: "HTTP-Kestrel", service: "Kestrel", probeType: "passive", matchRegex: `(?i)Server:\s*Kestrel`, priority: 87},
		{name: "HTTP-Traefik", service: "Traefik", probeType: "passive", matchRegex: `(?i)Server:\s*Traefik`, priority: 87},
		{name: "HTTP-HAProxy", service: "HAProxy", probeType: "passive", matchRegex: `(?i)Server:\s*HAProxy`, priority: 87},
		{name: "HTTP-WebLogic", service: "WebLogic", probeType: "passive", matchRegex: `(?i)Server:\s*WebLogic`, priority: 88, ports: "7001,7002"},
		{name: "HTTP-WebSphere", service: "WebSphere", probeType: "passive", matchRegex: `(?i)Server:\s*WebSphere`, priority: 88, ports: "9080,9443"},
		{name: "HTTP-WildFly", service: "WildFly", probeType: "passive", matchRegex: `(?i)Server:\s*WildFly[/ ]*([\d.]+)?`, priority: 87, ports: "8080,9990"},
		{name: "HTTP-GlassFish", service: "GlassFish", probeType: "passive", matchRegex: `(?i)Server:\s*GlassFish[/ ]*([\d.]+)?`, priority: 87, ports: "4848,8080"},
		{name: "HTTP-GoHTTP", service: "GoHTTP", probeType: "passive", matchRegex: `(?i)Server:\s*Go-http-server`, priority: 80},

		// --- Database ---
		{name: "MySQL-Banner", service: "MySQL", probeType: "passive", matchRegex: `(?i)mysql|MariaDB`, versionExpr: `([\d.]+(?:-MariaDB)?)`, priority: 85, ports: "3306"},
		{name: "PostgreSQL-Banner", service: "PostgreSQL", probeType: "passive", matchRegex: `(?i)PostgreSQL`, versionExpr: `([\d.]+)`, priority: 85, ports: "5432"},
		{name: "Redis-PONG", service: "Redis", probeType: "passive", matchRegex: `\+PONG`, priority: 90, ports: "6379"},
		{name: "Redis-Version", service: "Redis", probeType: "passive", matchRegex: `redis_version:([\d.]+)`, priority: 91, ports: "6379"},
		{name: "Redis-Error", service: "Redis", probeType: "passive", matchRegex: `(?i)-ERR.*redis`, priority: 80, ports: "6379"},
		{name: "Memcached-Version", service: "Memcached", probeType: "passive", matchRegex: `^VERSION\s+([\d.]+)`, priority: 90, ports: "11211"},
		{name: "MongoDB-Handshake", service: "MongoDB", probeType: "passive", matchRegex: `(?i)ismaster|isMaster|MongoDB`, priority: 80, ports: "27017"},
		{name: "Elasticsearch-JSON", service: "Elasticsearch", probeType: "passive", matchRegex: `(?i)"cluster_name"\s*:`, versionExpr: `"number"\s*:\s*"([\d.]+)"`, priority: 85, ports: "9200"},
		{name: "CouchDB-Banner", service: "CouchDB", probeType: "passive", matchRegex: `(?i)"couchdb"\s*:`, versionExpr: `"version"\s*:\s*"([\d.]+)"`, priority: 85, ports: "5984"},
		{name: "InfluxDB-Banner", service: "InfluxDB", probeType: "passive", matchRegex: `(?i)X-Influxdb-Version:\s*([\d.]+)`, priority: 85, ports: "8086"},
		{name: "ClickHouse-Banner", service: "ClickHouse", probeType: "passive", matchRegex: `(?i)X-ClickHouse-Summary|ClickHouse`, priority: 85, ports: "8123,9000"},
		{name: "Cassandra-CQL", service: "Cassandra", probeType: "passive", matchRegex: `(?i)cql_version`, priority: 80, ports: "9042"},
		{name: "TiDB-Banner", service: "TiDB", probeType: "passive", matchRegex: `(?i)TiDB`, versionExpr: `TiDB[- ]+([\d.]+)`, priority: 85, ports: "4000"},
		{name: "Cockroach-Banner", service: "CockroachDB", probeType: "passive", matchRegex: `(?i)CockroachDB`, priority: 80, ports: "26257"},

		// --- Remote Desktop / VNC ---
		{name: "RDP-Handshake", service: "RDP", probeType: "passive", matchRegex: `^\x03\x00\x00`, priority: 85, ports: "3389"},
		{name: "VNC-Banner", service: "VNC", probeType: "passive", matchRegex: `^RFB\s+([\d.]+)`, priority: 90, ports: "5900,5901,5902"},
		{name: "XRDP-Banner", service: "XRDP", probeType: "passive", matchRegex: `(?i)xrdp`, priority: 85, ports: "3389"},

		// --- Messaging & Queue ---
		{name: "AMQP-Banner", service: "RabbitMQ", probeType: "passive", matchRegex: `AMQP`, priority: 80, ports: "5672"},
		{name: "Kafka-Broker", service: "Kafka", probeType: "passive", matchRegex: `(?i)kafka`, priority: 75, ports: "9092"},
		{name: "NATS-Info", service: "NATS", probeType: "passive", matchRegex: `(?i)^INFO\s+\{.*"server_id"`, priority: 85, ports: "4222"},
		{name: "MQTT-ConnAck", service: "MQTT", probeType: "passive", matchRegex: `^\x20\x02`, priority: 80, ports: "1883,8883"},
		{name: "ActiveMQ-Banner", service: "ActiveMQ", probeType: "passive", matchRegex: `(?i)ActiveMQ`, priority: 80, ports: "61616"},
		{name: "RocketMQ-Banner", service: "RocketMQ", probeType: "passive", matchRegex: `(?i)RocketMQ`, priority: 80, ports: "9876"},
		{name: "NSQ-Banner", service: "NSQ", probeType: "passive", matchRegex: `(?i)"version".*nsq`, priority: 78, ports: "4150,4151"},

		// --- Mail ---
		{name: "POP3-Banner", service: "POP3", probeType: "passive", matchRegex: `^\+OK.*POP`, priority: 85, ports: "110,995"},
		{name: "IMAP-Banner", service: "IMAP", probeType: "passive", matchRegex: `^\*\s+OK.*IMAP`, priority: 85, ports: "143,993"},
		{name: "IMAP-Dovecot", service: "IMAP-Dovecot", probeType: "passive", matchRegex: `(?i)Dovecot`, priority: 87, ports: "143,993"},
		{name: "IMAP-Cyrus", service: "IMAP-Cyrus", probeType: "passive", matchRegex: `(?i)Cyrus\s+IMAP`, priority: 87, ports: "143,993"},

		// --- Directory / Auth ---
		{name: "LDAP-Result", service: "LDAP", probeType: "passive", matchRegex: `\x30[\x00-\xff]`, priority: 60, ports: "389,636"},
		{name: "Kerberos-Banner", service: "Kerberos", probeType: "passive", matchRegex: `\x30.*\xa0`, priority: 55, ports: "88"},

		// --- Container / Orchestration ---
		{name: "Docker-API", service: "Docker", probeType: "passive", matchRegex: `(?i)"ApiVersion"\s*:`, priority: 85, ports: "2375,2376"},
		{name: "K8s-API", service: "Kubernetes", probeType: "passive", matchRegex: `(?i)"kind"\s*:\s*"Status"`, priority: 80, ports: "6443,8443"},
		{name: "Zookeeper-Imok", service: "Zookeeper", probeType: "passive", matchRegex: `^imok`, priority: 90, ports: "2181"},
		{name: "Nomad-API", service: "Nomad", probeType: "passive", matchRegex: `(?i)"Region"\s*:.*"Datacenter"`, priority: 80, ports: "4646"},
		{name: "Vault-API", service: "Vault", probeType: "passive", matchRegex: `(?i)"initialized"\s*:`, priority: 80, ports: "8200"},
		{name: "Mesos-Banner", service: "Mesos", probeType: "passive", matchRegex: `(?i)"version"\s*:.*mesos`, priority: 75, ports: "5050,5051"},

		// --- Proxy / LB ---
		{name: "Squid-Banner", service: "Squid", probeType: "passive", matchRegex: `(?i)squid[/ ]*([\d.]+)?`, versionExpr: `squid[/ ]*([\d.]+)`, priority: 85, ports: "3128"},
		{name: "Envoy-Banner", service: "Envoy", probeType: "passive", matchRegex: `(?i)Server:\s*envoy`, priority: 85, ports: "8080,15001"},
		{name: "Varnish-Via", service: "Varnish", probeType: "passive", matchRegex: `(?i)Via:.*varnish`, priority: 85, ports: "80,6081"},

		// --- Misc TCP ---
		{name: "Telnet-Banner", service: "Telnet", probeType: "passive", matchRegex: `(?s)^\xff[\xfb\xfc\xfd\xfe]`, priority: 80, ports: "23"},
		{name: "Rsync-Banner", service: "Rsync", probeType: "passive", matchRegex: `^@RSYNCD:\s*([\d.]+)`, priority: 90, ports: "873"},
		{name: "SVN-Banner", service: "SVN", probeType: "passive", matchRegex: `^\(\s*success\s*\(\s*[\d]\s`, priority: 85, ports: "3690"},
		{name: "Git-Banner", service: "Git", probeType: "passive", matchRegex: `^ERR|^[0-9a-f]{4}#`, priority: 75, ports: "9418"},
		{name: "PPTP-Banner", service: "PPTP", probeType: "passive", matchRegex: `\x00\x01\x00\x01`, priority: 70, ports: "1723"},
		{name: "AJP-Banner", service: "AJP", probeType: "passive", matchRegex: `^AB`, priority: 75, ports: "8009"},
		{name: "MSSQL-Banner", service: "MSSQL", probeType: "passive", matchRegex: `\x04\x01`, priority: 70, ports: "1433"},
		{name: "Oracle-TNS", service: "Oracle", probeType: "passive", matchRegex: `\x00[\x00-\xff]\x00[\x00-\xff]\x00\x06`, priority: 70, ports: "1521"},

		// --- ICS/SCADA/IoT (工控) ---
		{name: "Modbus-Banner", service: "Modbus", probeType: "passive", matchRegex: `^\x00[\x00-\xff]\x00\x00\x00`, priority: 75, ports: "502"},
		{name: "S7Comm-Banner", service: "S7Comm", probeType: "passive", matchRegex: `^\x03\x00\x00\x16`, priority: 75, ports: "102"},
		{name: "BACnet-Banner", service: "BACnet", probeType: "passive", matchRegex: `^\x81`, priority: 70, ports: "47808"},
		{name: "DNP3-Banner", service: "DNP3", probeType: "passive", matchRegex: `^\x05\x64`, priority: 75, ports: "20000"},
		{name: "EtherNetIP-Banner", service: "EtherNet/IP", probeType: "passive", matchRegex: `^\x65\x00`, priority: 75, ports: "44818"},
		{name: "Codesys-Banner", service: "CODESYS", probeType: "passive", matchRegex: `(?i)codesys|3s-smart`, priority: 70, ports: "2455"},
		{name: "OPC-UA-Banner", service: "OPC-UA", probeType: "passive", matchRegex: `(?i)opc\.tcp`, priority: 75, ports: "4840"},
		{name: "FINS-Banner", service: "FINS", probeType: "passive", matchRegex: `^\x46\x49\x4e\x53`, priority: 75, ports: "9600"},
		{name: "Niagara-Fox", service: "NiagaraFox", probeType: "passive", matchRegex: `(?i)fox`, priority: 70, ports: "1911"},
		{name: "MQTT-IoT", service: "MQTT", probeType: "passive", matchRegex: `(?i)MQTT`, priority: 78, ports: "1883,8883"},

		// --- Monitoring / CI ---
		{name: "Jenkins-Banner", service: "Jenkins", probeType: "passive", matchRegex: `(?i)X-Jenkins:\s*([\d.]+)?`, priority: 88, ports: "8080"},
		{name: "GitLab-Banner", service: "GitLab", probeType: "passive", matchRegex: `(?i)gitlab`, priority: 80, ports: "80,443,8080"},
		{name: "Sonarqube-Banner", service: "SonarQube", probeType: "passive", matchRegex: `(?i)sonarqube`, priority: 80, ports: "9000"},
		{name: "Nexus-Banner", service: "Nexus", probeType: "passive", matchRegex: `(?i)nexus`, priority: 78, ports: "8081"},
		{name: "Artifactory-Banner", service: "Artifactory", probeType: "passive", matchRegex: `(?i)artifactory`, priority: 78, ports: "8081,8082"},
		{name: "Kibana-Banner", service: "Kibana", probeType: "passive", matchRegex: `(?i)kbn-name`, priority: 85, ports: "5601"},
		{name: "Grafana-Set-Cookie", service: "Grafana", probeType: "passive", matchRegex: `(?i)grafana_session`, priority: 85, ports: "3000"},
		{name: "Nacos-Banner", service: "Nacos", probeType: "passive", matchRegex: `(?i)nacos`, priority: 80, ports: "8848"},
		{name: "Apollo-Banner", service: "Apollo", probeType: "passive", matchRegex: `(?i)apollo`, priority: 75, ports: "8070,8080"},
		{name: "Zabbix-Agent", service: "Zabbix", probeType: "passive", matchRegex: `(?i)ZBXD`, priority: 80, ports: "10050,10051"},
		{name: "MinIO-Banner", service: "MinIO", probeType: "passive", matchRegex: `(?i)Server:\s*MinIO`, priority: 85, ports: "9000,9001"},
		{name: "Harbor-Banner", service: "Harbor", probeType: "passive", matchRegex: `(?i)harbor`, priority: 78, ports: "80,443"},

		// ============================================================
		// 主动探测 (active) — 发送 Probe 后匹配响应
		// ============================================================

		// --- HTTP 探测 ---
		{name: "Probe-HTTP", service: "HTTP", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `^HTTP/[\d.]+ \d{3}`, priority: 80, ports: "80,8080,8000,8008,8888,8090,3000,5000,9090"},
		{name: "Probe-HTTPS", service: "HTTPS", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `^HTTP/[\d.]+ \d{3}`, priority: 80, ports: "443,8443,9443"},

		// --- 邮件 ---
		{name: "Probe-SMTP-EHLO", service: "SMTP", probeType: "active", probeData: "EHLO probe\\r\\n", matchRegex: `^250[\s-]`, priority: 75, ports: "25,465,587"},
		{name: "Probe-POP3", service: "POP3", probeType: "active", probeData: "QUIT\\r\\n", matchRegex: `^\+OK`, priority: 75, ports: "110,995"},
		{name: "Probe-IMAP", service: "IMAP", probeType: "active", probeData: "a001 CAPABILITY\\r\\n", matchRegex: `^\*\s+`, priority: 75, ports: "143,993"},

		// --- 文件传输 ---
		{name: "Probe-FTP", service: "FTP", probeType: "active", probeData: "USER anonymous\\r\\n", matchRegex: `^331|^230|^530`, priority: 75, ports: "21"},
		{name: "Probe-TFTP", service: "TFTP", probeType: "active", probeData: "", matchRegex: ``, priority: 50, ports: "69"},

		// --- 数据库 ---
		{name: "Probe-Redis", service: "Redis", probeType: "active", probeData: "PING\\r\\n", matchRegex: `\+PONG`, priority: 90, ports: "6379"},
		{name: "Probe-Redis-Info", service: "Redis", probeType: "active", probeData: "INFO\\r\\n", matchRegex: `redis_version:([\d.]+)`, priority: 91, ports: "6379"},
		{name: "Probe-MySQL", service: "MySQL", probeType: "active", probeData: "", matchRegex: `(?i)mysql|MariaDB`, priority: 80, ports: "3306"},
		{name: "Probe-PgSQL", service: "PostgreSQL", probeType: "active", probeData: "\\0\\0\\0\\x08\\0\\x03\\0\\0", matchRegex: `(?i)postgres|authentication`, priority: 80, ports: "5432"},
		{name: "Probe-Mongo", service: "MongoDB", probeType: "active", probeData: "", matchRegex: `(?i)ismaster|errmsg`, priority: 75, ports: "27017"},
		{name: "Probe-Memcached", service: "Memcached", probeType: "active", probeData: "version\\r\\n", matchRegex: `^VERSION\s+([\d.]+)`, priority: 90, ports: "11211"},
		{name: "Probe-MSSQL", service: "MSSQL", probeType: "active", probeData: "", matchRegex: `\x04\x01`, priority: 70, ports: "1433"},
		{name: "Probe-CouchDB", service: "CouchDB", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"couchdb"`, priority: 80, ports: "5984"},
		{name: "Probe-ClickHouse", service: "ClickHouse", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)Ok\\.`, priority: 78, ports: "8123"},
		{name: "Probe-InfluxDB", service: "InfluxDB", probeType: "active", probeData: "GET /ping HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)X-Influxdb`, priority: 80, ports: "8086"},
		{name: "Probe-Cassandra", service: "Cassandra", probeType: "active", probeData: "", matchRegex: `(?i)cql_version`, priority: 75, ports: "9042"},
		{name: "Probe-Neo4j", service: "Neo4j", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)neo4j`, priority: 78, ports: "7474,7687"},

		// --- 流媒体/通信 ---
		{name: "Probe-RTSP", service: "RTSP", probeType: "active", probeData: "OPTIONS rtsp://probe RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n", matchRegex: `RTSP/[\d.]+ \d{3}`, priority: 80, ports: "554,8554"},
		{name: "Probe-SIP", service: "SIP", probeType: "active", probeData: "OPTIONS sip:probe SIP/2.0\\r\\nVia: SIP/2.0/TCP probe\\r\\nMax-Forwards: 0\\r\\nContent-Length: 0\\r\\n\\r\\n", matchRegex: `SIP/2.0 \d{3}`, priority: 80, ports: "5060,5061"},

		// --- DNS ---
		{name: "Probe-DNS", service: "DNS", probeType: "active", probeData: "", matchRegex: ``, priority: 60, ports: "53"},

		// --- 分布式/服务注册 ---
		{name: "Probe-Zookeeper", service: "Zookeeper", probeType: "active", probeData: "ruok", matchRegex: `^imok`, priority: 90, ports: "2181"},
		{name: "Probe-Elasticsearch", service: "Elasticsearch", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"cluster_name"`, priority: 85, ports: "9200"},
		{name: "Probe-RabbitMQ", service: "RabbitMQ", probeType: "active", probeData: "GET /api/overview HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)rabbitmq|management_version`, priority: 80, ports: "15672"},
		{name: "Probe-Docker", service: "Docker", probeType: "active", probeData: "GET /version HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"ApiVersion"`, priority: 85, ports: "2375,2376"},
		{name: "Probe-K8s", service: "Kubernetes", probeType: "active", probeData: "GET /version HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"gitVersion"`, priority: 85, ports: "6443"},
		{name: "Probe-Consul", service: "Consul", probeType: "active", probeData: "GET /v1/agent/self HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)"Config".*"Datacenter"`, priority: 80, ports: "8500"},
		{name: "Probe-Etcd", service: "etcd", probeType: "active", probeData: "GET /version HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"etcdserver"`, priority: 85, ports: "2379"},
		{name: "Probe-Prometheus", service: "Prometheus", probeType: "active", probeData: "GET /api/v1/status/buildinfo HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"goVersion"`, priority: 80, ports: "9090"},
		{name: "Probe-Grafana", service: "Grafana", probeType: "active", probeData: "GET /api/health HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)"database"\s*:\s*"ok"`, priority: 80, ports: "3000"},
		{name: "Probe-Nacos", service: "Nacos", probeType: "active", probeData: "GET /nacos/ HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)nacos`, priority: 80, ports: "8848"},
		{name: "Probe-Vault", service: "Vault", probeType: "active", probeData: "GET /v1/sys/health HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)"initialized"`, priority: 80, ports: "8200"},
		{name: "Probe-Nomad", service: "Nomad", probeType: "active", probeData: "GET /v1/status/leader HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `"\d+\.\d+\.\d+\.\d+:\d+"`, priority: 78, ports: "4646"},
		{name: "Probe-NATS", service: "NATS", probeType: "active", probeData: "PING\\r\\n", matchRegex: `PONG`, priority: 85, ports: "4222"},

		// --- CI/CD / DevOps ---
		{name: "Probe-Jenkins", service: "Jenkins", probeType: "active", probeData: "GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)X-Jenkins`, priority: 85, ports: "8080"},
		{name: "Probe-GitLab", service: "GitLab", probeType: "active", probeData: "GET /api/v4/version HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)"version"`, priority: 78, ports: "80,443,8080"},
		{name: "Probe-SonarQube", service: "SonarQube", probeType: "active", probeData: "GET /api/system/status HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)"status"`, priority: 78, ports: "9000"},
		{name: "Probe-MinIO", service: "MinIO", probeType: "active", probeData: "GET /minio/health/live HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `HTTP/[\d.]+ 200`, priority: 80, ports: "9000"},
		{name: "Probe-Harbor", service: "Harbor", probeType: "active", probeData: "GET /api/v2.0/health HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)"status"\s*:\s*"healthy"`, priority: 78, ports: "80,443"},
		{name: "Probe-Kibana", service: "Kibana", probeType: "active", probeData: "GET /api/status HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n", matchRegex: `(?i)kibana`, priority: 80, ports: "5601"},

		// --- ICS/SCADA ---
		{name: "Probe-Modbus", service: "Modbus", probeType: "active", probeData: "", matchRegex: `^\x00[\x00-\xff]\x00\x00\x00`, priority: 70, ports: "502"},
		{name: "Probe-S7Comm", service: "S7Comm", probeType: "active", probeData: "", matchRegex: `^\x03\x00`, priority: 70, ports: "102"},
		{name: "Probe-BACnet", service: "BACnet", probeType: "active", probeData: "", matchRegex: `^\x81`, priority: 65, ports: "47808"},
		{name: "Probe-OPC-UA", service: "OPC-UA", probeType: "active", probeData: "", matchRegex: `(?i)opc`, priority: 65, ports: "4840"},

		// --- Misc ---
		{name: "Probe-Rsync", service: "Rsync", probeType: "active", probeData: "", matchRegex: `^@RSYNCD`, priority: 85, ports: "873"},
		{name: "Probe-SVN", service: "SVN", probeType: "active", probeData: "", matchRegex: `^\(\s*success`, priority: 80, ports: "3690"},
		{name: "Probe-Socks5", service: "SOCKS5", probeType: "active", probeData: "\\x05\\x01\\x00", matchRegex: `^\x05[\x00\xff]`, priority: 80, ports: "1080"},
		{name: "Probe-Zabbix", service: "Zabbix", probeType: "active", probeData: "", matchRegex: `(?i)ZBXD`, priority: 78, ports: "10050,10051"},
	}
}

func defaultPortMap() map[int]string {
	return map[int]string{
		// Well-known (0-1023)
		20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
		80: "HTTP", 88: "Kerberos", 102: "S7Comm", 110: "POP3", 111: "RPC",
		119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
		138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
		162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS",
		445: "SMB", 464: "Kerberos-Pwd", 465: "SMTPS",
		500: "IKE", 502: "Modbus",
		512: "Rexec", 513: "Rlogin", 514: "Syslog", 515: "LPD", 520: "RIP",
		548: "AFP", 554: "RTSP", 587: "SMTP-Submission",
		631: "IPP", 636: "LDAPS", 873: "Rsync", 902: "VMware",
		993: "IMAPS", 995: "POP3S",

		// Registered (1024-49151)
		1080: "SOCKS", 1099: "RMI", 1194: "OpenVPN",
		1433: "MSSQL", 1434: "MSSQL-Browser",
		1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 1911: "NiagaraFox",
		2049: "NFS", 2121: "FTP-Alt", 2181: "Zookeeper",
		2375: "Docker", 2376: "Docker-TLS", 2379: "etcd", 2380: "etcd-Peer",
		2455: "CODESYS",
		3000: "Grafana", 3128: "Squid", 3306: "MySQL",
		3389: "RDP", 3478: "STUN", 3690: "SVN",
		4000: "TiDB", 4150: "NSQ", 4151: "NSQ-HTTP",
		4222: "NATS", 4369: "EPMD",
		4443: "HTTPS-Alt", 4646: "Nomad", 4840: "OPC-UA", 4848: "GlassFish",
		5000: "Docker-Registry", 5050: "Mesos-Master", 5051: "Mesos-Agent",
		5060: "SIP", 5061: "SIP-TLS",
		5222: "XMPP-Client", 5269: "XMPP-Server",
		5353: "mDNS", 5432: "PostgreSQL", 5555: "ADB",
		5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5901: "VNC-1", 5902: "VNC-2",
		5984: "CouchDB",
		6000: "X11", 6379: "Redis", 6443: "Kubernetes", 6666: "IRC",
		7001: "WebLogic", 7002: "WebLogic-SSL", 7474: "Neo4j-HTTP", 7687: "Neo4j-Bolt",
		8000: "HTTP-Alt", 8008: "HTTP-Alt", 8009: "AJP",
		8070: "Apollo", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8082: "Artifactory",
		8086: "InfluxDB", 8088: "HTTP-Alt", 8090: "HTTP-Alt",
		8123: "ClickHouse-HTTP", 8161: "ActiveMQ-Console",
		8200: "Vault", 8443: "HTTPS-Alt",
		8500: "Consul", 8554: "RTSP-Alt",
		8848: "Nacos", 8883: "MQTT-TLS",
		8888: "HTTP-Alt", 8899: "HTTP-Alt",
		9000: "SonarQube", 9001: "MinIO-Console",
		9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka",
		9093: "Alertmanager", 9100: "JetDirect",
		9200: "Elasticsearch", 9300: "ES-Transport",
		9418: "Git", 9443: "HTTPS-Alt", 9600: "FINS",
		9876: "RocketMQ", 9999: "HTTP-Alt",
		10000: "Webmin", 10050: "Zabbix-Agent", 10051: "Zabbix-Server",
		11211: "Memcached", 11300: "Beanstalkd",
		15001: "Envoy", 15672: "RabbitMQ-Mgmt",
		20000: "DNP3", 25565: "Minecraft",
		26257: "CockroachDB", 27017: "MongoDB", 27018: "MongoDB-Shard",
		28017: "MongoDB-Web",

		// Dynamic/Private (49152-65535) and other
		44818: "EtherNet/IP", 47808: "BACnet",
		50000: "SAP", 50030: "Hadoop-JobTracker",
		50070: "Hadoop-NameNode",
		61616: "ActiveMQ", 61617: "ActiveMQ-SSL",
	}
}
