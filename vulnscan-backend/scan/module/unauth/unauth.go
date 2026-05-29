package unauth

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type UnauthScanner struct{}

func New() *UnauthScanner { return &UnauthScanner{} }

func (m *UnauthScanner) ID() string       { return "unauth" }
func (m *UnauthScanner) Name() string     { return "未授权访问检测" }
func (m *UnauthScanner) Category() string { return "vuln" }

type serviceChecker func(ctx context.Context, host string, port int) *core.Finding

// 服务检测映射，根据服务名称而非端口
var serviceCheckers = map[string]serviceChecker{
	"redis":         checkRedis,
	"mongodb":       checkMongoDB,
	"memcached":     checkMemcached,
	"elasticsearch": checkElasticsearch,
	"docker":        checkDockerAPI,
	"zookeeper":     checkZookeeper,
	"hadoop-hdfs":   checkHadoopHDFS,
	"hadoop-yarn":   checkHadoopYARN,
	"couchdb":       checkCouchDB,
	"cassandra":     checkCassandra,
	"postgresql":    checkPostgreSQL,
	"rabbitmq":      checkRabbitMQManagement,
	"mysql":         checkMySQL,
	"ftp":           checkFTP,
	"vnc":           checkVNC,
	"jenkins":       checkJenkins,
	"jupyter":       checkJupyter,
	"kibana":        checkKibana,
	"grafana":       checkGrafana,
	"prometheus":    checkPrometheus,
	"consul":        checkConsul,
	"etcd":          checkEtcd,
	"clickhouse":    checkClickHouse,
	"influxdb":      checkInfluxDB,
	"solr":          checkSolr,
	"spark":         checkSpark,
	"airflow":       checkAirflow,
	"nacos":         checkNacos,
	"apollo":        checkApollo,
	"druid":         checkDruid,
	"jboss":         checkJBoss,
	"weblogic":      checkWebLogic,
	"tomcat":        checkTomcat,
	"activemq":      checkActiveMQ,
	"kafka":         checkKafka,
}

func (m *UnauthScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 20)

	for _, t := range targets {
		if t.Port <= 0 {
			continue
		}

		host := t.Host
		if t.IP != "" {
			host = t.IP
		}

		// 首先尝试通过服务名称检测（Service / Protocol / Extra.service）
		serviceDetected := false
		if svc := targetServiceName(t); svc != "" {
			if checker, ok := serviceCheckers[svc]; ok {
				select {
				case <-ctx.Done():
					result.Duration = time.Since(start)
					return result, ctx.Err()
				default:
				}

				wg.Add(1)
				sem <- struct{}{}
				go func(target *core.Target, chk serviceChecker) {
					defer wg.Done()
					defer func() { <-sem }()

					finding := chk(ctx, host, target.Port)
					if finding != nil {
						finding.Target = target
						mu.Lock()
						result.Findings = append(result.Findings, finding)
						mu.Unlock()
					}
				}(t, checker)

				serviceDetected = true
			}
		}

		// 如果服务名称未识别，尝试基于端口进行推测
		if !serviceDetected {
			// 检查是否为已知的非标准端口服务
			for serviceName, checker := range serviceCheckers {
				if isServiceLikelyOnPort(serviceName, t.Port) {
					select {
					case <-ctx.Done():
						result.Duration = time.Since(start)
						return result, ctx.Err()
					default:
					}

					wg.Add(1)
					sem <- struct{}{}
					go func(target *core.Target, chk serviceChecker) {
						defer wg.Done()
						defer func() { <-sem }()

						finding := chk(ctx, host, target.Port)
						if finding != nil {
							finding.Target = target
							mu.Lock()
							result.Findings = append(result.Findings, finding)
							mu.Unlock()
						}
					}(t, checker)

					serviceDetected = true
					break
				}
			}
		}

		// 如果仍然未检测到，尝试通用检测
		if !serviceDetected {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(target *core.Target) {
				defer wg.Done()
				defer func() { <-sem }()

				for serviceName, checker := range serviceCheckers {
					if isLikelyUnauthService(serviceName) {
						finding := checker(ctx, host, target.Port)
						if finding != nil {
							finding.Target = target
							mu.Lock()
							result.Findings = append(result.Findings, finding)
							mu.Unlock()
							break
						}
					}
				}
			}(t)
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[Unauth] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration.Round(time.Millisecond),
	)

	return result, nil
}

// 根据端口号判断是否可能是某种服务
func isServiceLikelyOnPort(serviceName string, port int) bool {
	switch serviceName {
	case "redis":
		return port == 6379 || port == 6380 || (port >= 6370 && port <= 6390)
	case "mongodb":
		return port >= 27000 && port <= 28000
	case "elasticsearch":
		return port >= 9200 && port <= 9400
	case "memcached":
		return port >= 11000 && port <= 12000
	case "docker":
		return port >= 2370 && port <= 2380
	case "zookeeper":
		return port >= 2100 && port <= 2200
	case "cassandra":
		return port >= 9000 && port <= 9100
	case "postgresql":
		return port >= 5400 && port <= 5500
	case "rabbitmq":
		return port >= 15670 && port <= 15680
	case "couchdb":
		return port >= 5900 && port <= 6000
	case "hadoop-hdfs":
		return port >= 50000 && port <= 51000
	case "hadoop-yarn":
		return port >= 8000 && port <= 9000
	case "mysql":
		return port >= 3300 && port <= 3400
	case "ftp":
		return port >= 20 && port <= 25
	case "vnc":
		return port >= 5800 && port <= 5999
	case "jenkins":
		return port >= 8000 && port <= 9000
	case "jupyter":
		return port >= 8800 && port <= 8900
	case "kibana":
		return port >= 5600 && port <= 5700
	case "grafana":
		return port >= 3000 && port <= 3100
	case "prometheus":
		return port >= 9090 && port <= 9100
	case "consul":
		return port >= 8500 && port <= 8600
	case "etcd":
		return port >= 2379 && port <= 2380
	case "clickhouse":
		return port >= 8123 && port <= 8124
	case "influxdb":
		return port >= 8086 && port <= 8090
	case "solr":
		return port >= 8983 && port <= 8985
	case "spark":
		return port >= 7077 && port <= 7080
	case "airflow":
		return port >= 8080 && port <= 8090
	case "nacos":
		return port >= 8848 && port <= 8850
	case "apollo":
		return port >= 8070 && port <= 8080
	case "druid":
		return port >= 8082 && port <= 8090
	case "jboss":
		return port >= 8080 && port <= 8100
	case "weblogic":
		return port >= 7001 && port <= 7010
	case "tomcat":
		return port >= 8080 && port <= 8090
	case "activemq":
		return port >= 8161 && port <= 8170
	case "kafka":
		return port >= 9092 && port <= 9100
	default:
		return false
	}
}

// 判断是否为可能的未授权服务（用于通用检测）
func isLikelyUnauthService(serviceName string) bool {
	// 仅对一些相对无害的协议进行通用检测
	return serviceName == "redis" ||
		serviceName == "elasticsearch" ||
		serviceName == "memcached" ||
		serviceName == "couchdb" ||
		serviceName == "zookeeper"
}

func targetServiceName(t *core.Target) string {
	if t == nil {
		return ""
	}
	if s := strings.TrimSpace(t.Service); s != "" {
		return strings.ToLower(s)
	}
	if s := strings.TrimSpace(t.Protocol); s != "" {
		lower := strings.ToLower(s)
		if lower != "tcp" && lower != "udp" {
			return lower
		}
	}
	if t.Extra != nil {
		if s := strings.TrimSpace(t.Extra["service"]); s != "" {
			return strings.ToLower(s)
		}
	}
	return ""
}

func checkRedis(ctx context.Context, host string, port int) *core.Finding {
	ok, version, evidence := probeRedisUnauth(ctx, host, port)
	if !ok {
		return nil
	}
	return &core.Finding{
		ModuleID: "unauth",
		Type:     "unauthorized_access",
		Title:    fmt.Sprintf("Redis 未授权访问 - %s:%d", host, port),
		Description: fmt.Sprintf(
			"Redis 服务 (%s:%d) 在未认证情况下响应 PING/INFO，攻击者可直接执行任意命令。版本: %s",
			host, port, version,
		),
		Severity:           "critical",
		Confidence:         95,
		ConfidenceReason:   "PING 返回 PONG 或 INFO 返回 redis_version",
		Evidence:           evidence,
		VerificationLevel:  core.VerifyExploit,
		VerificationDetail: "已发送 Redis 协议 PING/INFO 并读取响应",
		Timestamp:          time.Now(),
		Data: map[string]string{
			"service": "redis",
			"version": version,
			"port":    fmt.Sprintf("%d", port),
			"check":   "PING/INFO",
			"proof":   truncateEvidence(evidence, 512),
		},
	}
}

// probeRedisUnauth 探测 Redis 是否无需认证即可执行命令。
func probeRedisUnauth(ctx context.Context, host string, port int) (ok bool, version, evidence string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	reader := bufio.NewReader(conn)
	var lines []string

	_, _ = conn.Write([]byte("PING\r\n"))
	if line, err := reader.ReadString('\n'); err == nil {
		lines = append(lines, strings.TrimSpace(line))
		if strings.Contains(line, "+PONG") {
			ok = true
		}
	}

	_, _ = conn.Write([]byte("INFO server\r\n"))
	infoLines, ver := readRedisInfoBlock(reader)
	if len(infoLines) > 0 {
		lines = append(lines, infoLines...)
		if ver != "" && ver != "unknown" {
			version = ver
			ok = true
		}
	}
	if !ok {
		// 部分实例拒绝 PING 但仍对 INFO 返回版本（或 -NOAUTH 后仍可读）
		for _, l := range lines {
			if strings.Contains(l, "redis_version") {
				ok = true
				break
			}
		}
	}
	if version == "" {
		version = "unknown"
	}
	if len(lines) > 0 {
		evidence = strings.Join(lines, "\n")
	}
	return ok, version, evidence
}

func readRedisInfoBlock(r *bufio.Reader) ([]string, string) {
	var lines []string
	version := ""
	for i := 0; i < 40; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if strings.Contains(line, "redis_version") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				version = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "+") {
			if i > 0 {
				break
			}
		}
	}
	return lines, version
}

func truncateEvidence(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func checkMySQL(ctx context.Context, host string, port int) *core.Finding {
	for _, user := range []string{"root", "mysql", ""} {
		ok, version, evidence := probeMySQLEmptyAuth(ctx, host, port, user)
		if !ok {
			continue
		}
		userLabel := user
		if userLabel == "" {
			userLabel = "(空用户名)"
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("MySQL 弱口令/空密码 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"MySQL 服务 (%s:%d) 用户 %s 可使用空密码登录。版本: %s",
				host, port, userLabel, version,
			),
			Severity:           "critical",
			Confidence:         92,
			ConfidenceReason:   "空密码认证握手返回 OK",
			Evidence:           evidence,
			VerificationLevel:  core.VerifyExploit,
			VerificationDetail: fmt.Sprintf("已尝试用户 %s 空密码登录", userLabel),
			Timestamp:          time.Now(),
			Data: map[string]string{
				"service":  "mysql",
				"version":  version,
				"port":     fmt.Sprintf("%d", port),
				"username": user,
				"password": "",
				"check":    "mysql_native_password",
				"proof":    truncateEvidence(evidence, 512),
			},
		}
	}
	return nil
}

func probeMySQLEmptyAuth(ctx context.Context, host string, port int, user string) (bool, string, string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, "", ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 || buf[4] != 0x0a {
		return false, "", ""
	}

	version := extractMySQLVersion(buf[:n])
	if version == "unknown" {
		return false, "", ""
	}

	verEnd := 5
	for verEnd < n && buf[verEnd] != 0 {
		verEnd++
	}
	salt1End := verEnd + 5
	if salt1End+8 > n {
		return false, "", ""
	}
	salt1 := buf[salt1End : salt1End+8]
	capOffset := salt1End + 8 + 1
	restOffset := capOffset + 18
	if restOffset+12 > n {
		return false, "", ""
	}
	salt2 := buf[restOffset : restOffset+12]
	salt := append(salt1, salt2...)

	authUser := user
	if authUser == "" {
		authUser = "root"
	}
	authResp := mysqlNativePassword("", salt)
	pkt := buildMySQLAuthPacket(authUser, authResp)
	if _, err := conn.Write(pkt); err != nil {
		return false, "", ""
	}

	n, err = conn.Read(buf)
	if err != nil || n < 5 || buf[4] != 0x00 {
		return false, "", ""
	}

	evidence := fmt.Sprintf("greeting: %s\nauth: OK (user=%s, empty password)", version, authUser)
	return true, version, evidence
}

func extractMySQLVersion(buf []byte) string {
	if len(buf) < 5 {
		return "unknown"
	}

	resp := string(buf[5:])
	if idx := strings.Index(resp, "\x00"); idx != -1 {
		version := resp[:idx]
		if strings.Contains(version, "MySQL") || strings.Contains(version, "MariaDB") {
			return version
		}
	}
	return "unknown"
}

func mysqlNativePassword(password string, salt []byte) []byte {
	if password == "" {
		return nil
	}
	hash1 := md5sum([]byte(password))
	hash2 := md5sum(hash1)
	combined := append(salt, hash2...)
	hash3 := md5sum(combined)
	result := make([]byte, len(hash1))
	for i := range hash1 {
		result[i] = hash1[i] ^ hash3[i]
	}
	return result
}

func md5sum(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func buildMySQLAuthPacket(user string, authResp []byte) []byte {
	payload := make([]byte, 0, 128)
	capBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(capBuf, 0x0003a685)
	payload = append(payload, capBuf...)
	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, 16777216)
	payload = append(payload, sizeBuf...)
	payload = append(payload, 0x21)
	payload = append(payload, make([]byte, 23)...)
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0)
	if authResp != nil {
		payload = append(payload, byte(len(authResp)))
		payload = append(payload, authResp...)
	} else {
		payload = append(payload, 0)
	}
	pktLen := len(payload)
	header := make([]byte, 4)
	header[0] = byte(pktLen)
	header[1] = byte(pktLen >> 8)
	header[2] = byte(pktLen >> 16)
	header[3] = 1
	return append(header, payload...)
}

func checkFTP(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if !strings.HasPrefix(resp, "220") {
		return nil
	}

	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		return nil
	}

	resp, err = reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if strings.HasPrefix(resp, "331") {
		_, err = conn.Write([]byte("PASS anonymous@\r\n"))
		if err != nil {
			return nil
		}

		resp, err = reader.ReadString('\n')
		if err != nil {
			return nil
		}

		if strings.HasPrefix(resp, "230") {
			return &core.Finding{
				ModuleID: "unauth",
				Type:     "unauthorized_access",
				Title:    fmt.Sprintf("FTP 匿名登录 - %s:%d", host, port),
				Description: fmt.Sprintf(
					"FTP 服务 (%s:%d) 允许匿名登录，可能导致敏感文件泄露。",
					host, port,
				),
				Severity:   "high",
				Confidence: 95,
				Timestamp:  time.Now(),
				Data: map[string]string{
					"service": "ftp",
					"port":    fmt.Sprintf("%d", port),
				},
			}
		}
	}

	return nil
}

func checkVNC(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil
	}

	if !strings.HasPrefix(string(buf[:n]), "RFB ") {
		return nil
	}

	version := strings.TrimSpace(string(buf[:n]))

	_, err = conn.Write(buf[:n])
	if err != nil {
		return nil
	}

	n, err = conn.Read(buf)
	if err != nil || n < 4 {
		return nil
	}

	if n >= 4 && buf[3] == 0x01 {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("VNC 未授权访问（无密码）- %s:%d", host, port),
			Description: fmt.Sprintf(
				"VNC 服务 (%s:%d) 无需密码即可连接，攻击者可远程控制桌面。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "vnc",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkJenkins(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/login", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Jenkins") && strings.Contains(bodyStr, "dashboard") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Jenkins 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Jenkins 服务 (%s:%d) 允许未授权访问，攻击者可执行任意构建命令。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "jenkins",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkJupyter(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/api", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var jupyterResp map[string]interface{}
	if err := json.Unmarshal(body, &jupyterResp); err != nil {
		return nil
	}

	if _, ok := jupyterResp["version"].(string); ok {
		version := ""
		if v, ok := jupyterResp["version"].(string); ok {
			version = v
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Jupyter Notebook 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Jupyter Notebook (%s:%d) 允许未授权访问，攻击者可执行任意代码。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "jupyter",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkKibana(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/api/status", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var kibanaResp map[string]interface{}
	if err := json.Unmarshal(body, &kibanaResp); err != nil {
		return nil
	}

	if status, ok := kibanaResp["status"].(map[string]interface{}); ok {
		if overall, ok := status["overall"].(map[string]interface{}); ok {
			if _, ok := overall["state"].(string); ok {
				version := ""
				if verObj, ok := kibanaResp["version"].(map[string]interface{}); ok {
					if v, ok := verObj["number"].(string); ok {
						version = v
					}
				}
				return &core.Finding{
					ModuleID: "unauth",
					Type:     "unauthorized_access",
					Title:    fmt.Sprintf("Kibana 未授权访问 - %s:%d", host, port),
					Description: fmt.Sprintf(
						"Kibana 服务 (%s:%d) 允许未授权访问，攻击者可查看 Elasticsearch 数据。版本: %s",
						host, port, version,
					),
					Severity:   "high",
					Confidence: 90,
					Timestamp:  time.Now(),
					Data: map[string]string{
						"service": "kibana",
						"version": version,
						"port":    fmt.Sprintf("%d", port),
					},
				}
			}
		}
	}

	return nil
}

func checkGrafana(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/api/health", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var grafanaResp map[string]interface{}
	if err := json.Unmarshal(body, &grafanaResp); err != nil {
		return nil
	}

	if database, ok := grafanaResp["database"].(string); ok && database == "ok" {
		version := ""
		if v, ok := grafanaResp["version"].(string); ok {
			version = v
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Grafana 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Grafana 服务 (%s:%d) 允许未授权访问，攻击者可查看监控数据。版本: %s",
				host, port, version,
			),
			Severity:   "medium",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "grafana",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkPrometheus(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/api/v1/status/config", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var promResp map[string]interface{}
	if err := json.Unmarshal(body, &promResp); err != nil {
		return nil
	}

	if status, ok := promResp["status"].(string); ok && status == "success" {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Prometheus 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Prometheus 服务 (%s:%d) 允许未授权访问，攻击者可查看监控指标和配置。",
				host, port,
			),
			Severity:   "medium",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "prometheus",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkConsul(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/v1/status/leader", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "\"") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Consul 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Consul 服务 (%s:%d) 允许未授权访问，攻击者可读取/写入服务注册信息。",
				host, port,
			),
			Severity:   "high",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "consul",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkEtcd(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/version", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var etcdResp map[string]interface{}
	if err := json.Unmarshal(body, &etcdResp); err != nil {
		return nil
	}

	if _, ok := etcdResp["etcdserver"].(string); ok {
		version := ""
		if v, ok := etcdResp["etcdserver"].(string); ok {
			version = v
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Etcd 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Etcd 服务 (%s:%d) 允许未授权访问，攻击者可读写键值对数据。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "etcd",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkClickHouse(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader("SELECT version()"))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	version := strings.TrimSpace(string(body))
	if len(version) > 0 && strings.Contains(version, ".") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("ClickHouse 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"ClickHouse 服务 (%s:%d) 允许未授权访问，攻击者可执行 SQL 查询。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "clickhouse",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkInfluxDB(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/ping", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return nil
	}

	version := resp.Header.Get("X-Influxdb-Version")
	if version != "" {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("InfluxDB 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"InfluxDB 服务 (%s:%d) 允许未授权访问，攻击者可读写时序数据。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "influxdb",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkSolr(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/solr/admin/info/system", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var solrResp map[string]interface{}
	if err := json.Unmarshal(body, &solrResp); err != nil {
		return nil
	}

	if _, ok := solrResp["lucene"].(map[string]interface{}); ok {
		version := ""
		if solrSpec, ok := solrResp["solr-spec-version"].(string); ok {
			version = solrSpec
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Apache Solr 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Apache Solr 服务 (%s:%d) 允许未授权访问，攻击者可执行搜索和读取数据。版本: %s",
				host, port, version,
			),
			Severity:   "high",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "solr",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkSpark(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/api/v1/applications", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var sparkResp []interface{}
	if err := json.Unmarshal(body, &sparkResp); err != nil {
		return nil
	}

	if len(sparkResp) > 0 {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Apache Spark 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Apache Spark Master (%s:%d) 允许未授权访问，攻击者可提交恶意任务。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "spark",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkAirflow(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/admin/", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Airflow") && strings.Contains(bodyStr, "DAGs") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Apache Airflow 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Apache Airflow (%s:%d) 允许未授权访问，攻击者可触发任意 DAG 执行。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "airflow",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkNacos(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/nacos/v1/cs/configs?dataId=&group=&tenant=&pageNo=1&pageSize=10", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var nacosResp map[string]interface{}
	if err := json.Unmarshal(body, &nacosResp); err != nil {
		return nil
	}

	if _, ok := nacosResp["pageItems"].([]interface{}); ok {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Nacos 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Nacos 服务 (%s:%d) 允许未授权访问，攻击者可读取配置信息。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "nacos",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkApollo(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/openapi/v1/env", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var apolloResp []interface{}
	if err := json.Unmarshal(body, &apolloResp); err != nil {
		return nil
	}

	if len(apolloResp) > 0 {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Apollo 配置中心未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Apollo 配置中心 (%s:%d) 允许未授权访问，攻击者可读取应用配置。",
				host, port,
			),
			Severity:   "high",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "apollo",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkDruid(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/druid/index.html", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Druid Stat Index") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Druid 监控面板未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Druid 监控面板 (%s:%d) 允许未授权访问，攻击者可查看数据库连接池和 SQL 执行信息。",
				host, port,
			),
			Severity:   "high",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "druid",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkJBoss(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/jmx-console/", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "JBoss") && strings.Contains(bodyStr, "JMX Console") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("JBoss JMX Console 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"JBoss JMX Console (%s:%d) 允许未授权访问，攻击者可执行管理操作。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "jboss",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkWebLogic(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/console", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "WebLogic") || strings.Contains(bodyStr, "Oracle") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("WebLogic Console未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"WebLogic Console (%s:%d) 允许未授权访问，攻击者可管理应用服务器。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 80,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "weblogic",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkTomcat(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/manager/html", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.SetBasicAuth("admin", "admin")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Tomcat") && strings.Contains(bodyStr, "Manager") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Tomcat Manager 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Tomcat Manager (%s:%d) 使用默认凭据 admin/admin 可访问，攻击者可部署恶意应用。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "tomcat",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkActiveMQ(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/admin/", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.SetBasicAuth("admin", "admin")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "ActiveMQ") {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("ActiveMQ 控制台未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"ActiveMQ 控制台 (%s:%d) 使用默认凭据 admin/admin 可访问，攻击者可管理消息队列。",
				host, port,
			),
			Severity:   "high",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "activemq",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkKafka(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	apiKey := int16(18)
	apiVersion := int16(0)
	correlationID := int32(0)
	clientID := "kafka-test"

	buf := make([]byte, 0, 64)

	buf = append(buf, 0, 0)

	buf = append(buf, byte(apiKey>>8), byte(apiKey&0xFF))
	buf = append(buf, byte(apiVersion>>8), byte(apiVersion&0xFF))
	buf = append(buf, byte(correlationID>>24), byte(correlationID>>16), byte(correlationID>>8), byte(correlationID&0xFF))

	clientIDBytes := []byte(clientID)
	buf = append(buf, byte(len(clientIDBytes)>>8), byte(len(clientIDBytes)&0xFF))
	buf = append(buf, clientIDBytes...)

	msgLen := len(buf) - 2
	buf[0] = byte(msgLen >> 8)
	buf[1] = byte(msgLen & 0xFF)

	_, err = conn.Write(buf)
	if err != nil {
		return nil
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil
	}

	if n > 0 {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Kafka 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Kafka 服务 (%s:%d) 允许未授权访问，攻击者可读写消息队列。",
				host, port,
			),
			Severity:   "high",
			Confidence: 80,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "kafka",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func extractRedisVersion(firstLine string, reader *bufio.Reader) string {
	if strings.Contains(firstLine, "redis_version") {
		parts := strings.SplitN(firstLine, ":", 3)
		if len(parts) == 3 {
			return strings.TrimSpace(parts[2])
		}
	}

	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(line, "redis_version") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 {
				return strings.TrimSpace(parts[2])
			}
		}
	}
	return "unknown"
}

func checkMongoDB(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	isMasterMsg := buildMongoDBIsMaster()
	_, err = conn.Write(isMasterMsg)
	if err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	if n > 0 && isValidMongoDBResponse(buf[:n]) {
		version := extractMongoDBVersion(buf[:n])
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("MongoDB 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"MongoDB 服务 (%s:%d) 允许未授权访问，攻击者可直接执行数据库操作。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "mongodb",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func buildMongoDBIsMaster() []byte {
	msgLen := 59
	requestID := 12345

	buf := make([]byte, msgLen)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	binary.LittleEndian.PutUint32(buf[12:16], 2004)

	buf[16] = 0
	copy(buf[17:], "admin.$cmd")

	payload := `{"ismaster": 1}`
	copy(buf[19:], payload)

	return buf
}

func isValidMongoDBResponse(buf []byte) bool {
	if len(buf) < 36 {
		return false
	}

	responseLen := binary.LittleEndian.Uint32(buf[0:4])
	if responseLen < 36 || responseLen > 4096 {
		return false
	}

	requestID := binary.LittleEndian.Uint32(buf[4:8])
	responseTo := binary.LittleEndian.Uint32(buf[8:12])
	opCode := binary.LittleEndian.Uint32(buf[12:16])

	if requestID != 0 && responseTo != requestID {
		return false
	}

	if opCode != 1 {
		return false
	}

	return true
}

func extractMongoDBVersion(buf []byte) string {
	resp := string(buf)
	if idx := strings.Index(resp, `"version"`); idx != -1 {
		rest := resp[idx:]
		if colonIdx := strings.Index(rest, `": "`); colonIdx != -1 {
			verStart := rest[colonIdx+4:]
			if endIdx := strings.Index(verStart, `"`); endIdx != -1 {
				return verStart[:endIdx]
			}
		}
	}
	return "unknown"
}

func checkMemcached(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("stats\r\n"))
	if err != nil {
		return nil
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if strings.HasPrefix(line, "STAT ") || strings.HasPrefix(line, "END") {
		version := extractMemcachedVersion(reader)
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Memcached 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Memcached 服务 (%s:%d) 允许未授权访问，可能导致数据泄露或被利用进行 DDoS 放大攻击。版本: %s",
				host, port, version,
			),
			Severity:   "high",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "memcached",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func extractMemcachedVersion(reader *bufio.Reader) string {
	for i := 0; i < 50; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "STAT version") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) == 3 {
				return strings.TrimSpace(parts[2])
			}
		}
		if line == "END\r\n" || line == "END" {
			break
		}
	}
	return "unknown"
}

func checkElasticsearch(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var esResp map[string]interface{}
	if err := json.Unmarshal(body, &esResp); err != nil {
		return nil
	}

	if tagline, ok := esResp["tagline"].(string); ok && strings.Contains(tagline, "Elasticsearch") {
		version := "unknown"
		if verObj, ok := esResp["version"].(map[string]interface{}); ok {
			if v, ok := verObj["number"].(string); ok {
				version = v
			}
		}
		clusterName := ""
		if name, ok := esResp["cluster_name"].(string); ok {
			clusterName = name
		}

		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Elasticsearch 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Elasticsearch 服务 (%s:%d) 允许未授权访问，攻击者可读取/修改/删除数据。集群: %s, 版本: %s",
				host, port, clusterName, version,
			),
			Severity:   "critical",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service":      "elasticsearch",
				"version":      version,
				"cluster_name": clusterName,
				"port":         fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkDockerAPI(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/version", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var dockerResp map[string]interface{}
	if err := json.Unmarshal(body, &dockerResp); err != nil {
		return nil
	}

	if _, ok := dockerResp["ApiVersion"].(string); ok {
		version := ""
		if v, ok := dockerResp["Version"].(string); ok {
			version = v
		}
		os := ""
		if o, ok := dockerResp["Os"].(string); ok {
			os = o
		}

		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Docker API 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Docker Remote API (%s:%d) 允许未授权访问，攻击者可完全控制 Docker 宿主机。版本: %s, 系统: %s",
				host, port, version, os,
			),
			Severity:   "critical",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "docker",
				"version": version,
				"os":      os,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkZookeeper(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("stat\r\n"))
	if err != nil {
		return nil
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if strings.Contains(resp, "Zookeeper version") || strings.Contains(resp, "Latency min/avg/max") {
		version := extractZookeeperVersion(resp, reader)
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Zookeeper 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Zookeeper 服务 (%s:%d) 允许未授权访问，攻击者可读取配置信息或执行管理命令。版本: %s",
				host, port, version,
			),
			Severity:   "high",
			Confidence: 90,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "zookeeper",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func extractZookeeperVersion(firstLine string, reader *bufio.Reader) string {
	if strings.Contains(firstLine, "Zookeeper version") {
		parts := strings.SplitN(firstLine, ":", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}

	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(line, "Zookeeper version") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}

func checkHadoopHDFS(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/jmx", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var hadoopResp map[string]interface{}
	if err := json.Unmarshal(body, &hadoopResp); err != nil {
		return nil
	}

	if beans, ok := hadoopResp["beans"].([]interface{}); ok && len(beans) > 0 {
		version := extractHadoopVersion(hadoopResp)
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Hadoop HDFS 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Hadoop HDFS NameNode JMX 接口 (%s:%d) 允许未授权访问，可能泄露集群敏感信息。版本: %s",
				host, port, version,
			),
			Severity:   "high",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "hadoop_hdfs",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func extractHadoopVersion(resp map[string]interface{}) string {
	if beans, ok := resp["beans"].([]interface{}); ok {
		for _, b := range beans {
			if bean, ok := b.(map[string]interface{}); ok {
				if name, ok := bean["name"].(string); ok && strings.Contains(name, "Hadoop") {
					if ver, ok := bean["HadoopVersion"].(string); ok {
						return ver
					}
				}
			}
		}
	}
	return "unknown"
}

func checkHadoopYARN(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/ws/v1/cluster/info", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var yarnResp map[string]interface{}
	if err := json.Unmarshal(body, &yarnResp); err != nil {
		return nil
	}

	if clusterInfo, ok := yarnResp["clusterInfo"].(map[string]interface{}); ok {
		if _, ok := clusterInfo["id"].(float64); ok {
			version := ""
			if v, ok := clusterInfo["hadoopVersion"].(string); ok {
				version = v
			}
			return &core.Finding{
				ModuleID: "unauth",
				Type:     "unauthorized_access",
				Title:    fmt.Sprintf("Hadoop YARN 未授权访问 - %s:%d", host, port),
				Description: fmt.Sprintf(
					"Hadoop YARN ResourceManager (%s:%d) 允许未授权访问，攻击者可提交恶意任务。版本: %s",
					host, port, version,
				),
				Severity:   "critical",
				Confidence: 90,
				Timestamp:  time.Now(),
				Data: map[string]string{
					"service": "hadoop_yarn",
					"version": version,
					"port":    fmt.Sprintf("%d", port),
				},
			}
		}
	}

	return nil
}

func checkCouchDB(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var couchResp map[string]interface{}
	if err := json.Unmarshal(body, &couchResp); err != nil {
		return nil
	}

	if couch, ok := couchResp["couchdb"].(string); ok && couch == "Welcome" {
		version := ""
		if v, ok := couchResp["version"].(string); ok {
			version = v
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("CouchDB 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"CouchDB 服务 (%s:%d) 允许未授权访问，攻击者可读写数据库。版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "couchdb",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func checkCassandra(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	optionsMsg := buildCassandraOptions()
	_, err = conn.Write(optionsMsg)
	if err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	if n > 0 && isValidCassandraResponse(buf[:n]) {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("Cassandra 未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"Cassandra 服务 (%s:%d) 允许未授权访问，攻击者可执行 CQL 查询。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 85,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "cassandra",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func buildCassandraOptions() []byte {
	msg := []byte{
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	return msg
}

func isValidCassandraResponse(buf []byte) bool {
	if len(buf) < 9 {
		return false
	}

	if buf[0] != 0x04 {
		return false
	}

	opcode := buf[4]
	if opcode == 0x00 || opcode == 0x02 || opcode == 0x03 || opcode == 0x05 {
		return true
	}

	return false
}

func checkPostgreSQL(ctx context.Context, host string, port int) *core.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	startupMsg := buildPostgreSQLStartup(host)
	_, err = conn.Write(startupMsg)
	if err != nil {
		return nil
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	if n > 0 && isPostgreSQLAuthResponse(buf[:n]) {
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("PostgreSQL 未授权访问（信任认证）- %s:%d", host, port),
			Description: fmt.Sprintf(
				"PostgreSQL 服务 (%s:%d) 配置为 trust 认证模式，允许未授权访问数据库。",
				host, port,
			),
			Severity:   "critical",
			Confidence: 80,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "postgresql",
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}

func buildPostgreSQLStartup(host string) []byte {
	user := "postgres"
	database := "postgres"

	params := fmt.Sprintf("user\x00%s\x00database\x00%s\x00\x00", user, database)

	msgLen := 4 + 4 + len(params)
	buf := make([]byte, msgLen)

	binary.BigEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.BigEndian.PutUint32(buf[4:8], 196608)

	copy(buf[8:], params)

	return buf
}

func isPostgreSQLAuthResponse(buf []byte) bool {
	if len(buf) < 5 {
		return false
	}

	msgType := buf[0]
	if msgType == 'R' {
		return true
	}

	if msgType == 'E' {
		return true
	}

	return false
}

func checkRabbitMQManagement(ctx context.Context, host string, port int) *core.Finding {
	url := fmt.Sprintf("http://%s:%d/api/overview", host, port)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.SetBasicAuth("guest", "guest")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil
	}

	var rabbitResp map[string]interface{}
	if err := json.Unmarshal(body, &rabbitResp); err != nil {
		return nil
	}

	if _, ok := rabbitResp["rabbitmq_version"].(string); ok {
		version := ""
		if v, ok := rabbitResp["rabbitmq_version"].(string); ok {
			version = v
		}
		return &core.Finding{
			ModuleID: "unauth",
			Type:     "unauthorized_access",
			Title:    fmt.Sprintf("RabbitMQ 管理界面未授权访问 - %s:%d", host, port),
			Description: fmt.Sprintf(
				"RabbitMQ 管理界面 (%s:%d) 使用默认凭据 guest/guest 可访问，版本: %s",
				host, port, version,
			),
			Severity:   "critical",
			Confidence: 95,
			Timestamp:  time.Now(),
			Data: map[string]string{
				"service": "rabbitmq",
				"version": version,
				"port":    fmt.Sprintf("%d", port),
			},
		}
	}

	return nil
}
