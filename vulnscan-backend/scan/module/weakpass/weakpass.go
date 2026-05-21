package weakpass

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"vulnscan-backend/dict"
	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
)

type WeakPassScanner struct {
	dictStore *dict.Store
}

func New(dictStore *dict.Store) *WeakPassScanner {
	if dictStore == nil {
		dictStore = dict.NewStore(nil)
	}
	return &WeakPassScanner{dictStore: dictStore}
}

func (m *WeakPassScanner) ID() string       { return "weak_pass" }
func (m *WeakPassScanner) Name() string     { return "弱口令检测" }
func (m *WeakPassScanner) Category() string { return "vuln" }

type credential struct {
	Username string
	Password string
}

type serviceChecker func(ctx context.Context, host string, port int, cred credential) (bool, string)

func (m *WeakPassScanner) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 20)

	for _, t := range targets {
		if t.Port <= 0 {
			continue
		}

		checker := m.getChecker(t)
		if checker == nil {
			continue
		}

		creds := m.getCredentials(t)
		host := t.Host
		if t.IP != "" {
			host = t.IP
		}

		for _, cred := range creds {
			select {
			case <-ctx.Done():
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(target *core.Target, c credential, chk serviceChecker) {
				defer wg.Done()
				defer func() { <-sem }()

				if ok, proof := chk(ctx, host, target.Port, c); ok {
					finding := &core.Finding{
						ModuleID:           m.ID(),
						Target:             target,
						Type:               "weak_password",
						Title:              weakPassFindingTitle(target, c),
						Description:        weakPassFindingDesc(target, c),
						Severity:           "critical",
						Confidence:         95,
						ConfidenceReason:   "协议层认证成功",
						Evidence:           proof,
						VerificationLevel:  core.VerifyExploit,
						VerificationDetail: "已完成登录/命令探测",
						Timestamp:          time.Now(),
						Data: map[string]string{
							"service":  serviceByPort(target.Port),
							"username": c.Username,
							"password": c.Password,
							"proof":    proof,
						},
					}

					mu.Lock()
					result.Findings = append(result.Findings, finding)
					mu.Unlock()
				}
			}(t, cred, checker)
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 弱口令检测完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *WeakPassScanner) getChecker(t *core.Target) serviceChecker {
	checkers := map[int]serviceChecker{
		21:    checkFTP,
		22:    checkSSH,
		3306:  checkMySQL,
		5432:  checkPostgres,
		6379:  checkRedis,
		27017: checkMongo,
	}

	if chk, ok := checkers[t.Port]; ok {
		return chk
	}
	return nil
}

func (m *WeakPassScanner) getCredentials(t *core.Target) []credential {
	passwords := m.dictStore.GetPasswords()
	if len(passwords) == 0 {
		payload.LogFallbackOnce("weakpass")
		passwords = payload.MinimalPasswords()
	} else if !m.dictStore.HasDBEntries(model.DictTypePassword) {
		slog.Debug("[weak_pass] 密码字典来自内嵌默认")
	}

	usernames := m.dictStore.GetUsernames()
	if len(usernames) == 0 {
		payload.LogFallbackOnce("weakpass")
		usernames = payload.MinimalUsernamesForPort(t.Port)
	} else {
		usernames = m.dictStore.Merge(usernames, payload.MinimalUsernamesForPort(t.Port))
	}

	var creds []credential
	for _, u := range usernames {
		for _, p := range passwords {
			creds = append(creds, credential{Username: u, Password: p})
		}
	}
	return creds
}

func checkFTP(ctx context.Context, host string, port int, cred credential) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "220") {
		return false, ""
	}

	_, _ = fmt.Fprintf(conn, "USER %s\r\n", cred.Username)
	n, err = conn.Read(buf)
	if err != nil {
		return false, ""
	}
	resp := string(buf[:n])

	if strings.HasPrefix(resp, "230") {
		return true, strings.TrimSpace(resp)
	}

	if strings.HasPrefix(resp, "331") {
		_, _ = fmt.Fprintf(conn, "PASS %s\r\n", cred.Password)
		n, err = conn.Read(buf)
		if err != nil {
			return false, ""
		}
		final := string(buf[:n])
		if strings.HasPrefix(final, "230") {
			return true, strings.TrimSpace(final)
		}
	}

	return false, ""
}

func checkSSH(ctx context.Context, host string, port int, cred credential) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	config := &ssh.ClientConfig{
		User: cred.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(cred.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false, ""
	}
	conn.Close()
	return true, fmt.Sprintf("SSH 登录成功 user=%s", cred.Username)
}

func checkMySQL(ctx context.Context, host string, port int, cred credential) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false, ""
	}

	if buf[4] != 0x0a {
		return false, ""
	}

	version := extractMySQLGreetingVersion(buf[:n])

	salt1End := 5
	for salt1End < n && buf[salt1End] != 0 {
		salt1End++
	}
	if salt1End+28 > n {
		return false, ""
	}

	salt1 := buf[salt1End+1 : salt1End+9]

	capOffset := salt1End + 9
	if capOffset+2 > n {
		return false, ""
	}

	restOffset := capOffset + 18
	if restOffset+12 > n {
		return false, ""
	}
	salt2 := buf[restOffset : restOffset+12]

	salt := append(salt1, salt2...)

	authResp := mysqlNativePassword(cred.Password, salt)

	pkt := buildMySQLAuthPacket(cred.Username, authResp)
	if _, err := conn.Write(pkt); err != nil {
		return false, ""
	}

	n, err = conn.Read(buf)
	if err != nil || n < 5 {
		return false, ""
	}

	if buf[4] != 0x00 {
		return false, ""
	}
	return true, fmt.Sprintf("MySQL auth OK user=%s version=%s", cred.Username, version)
}

func extractMySQLGreetingVersion(buf []byte) string {
	if len(buf) < 6 {
		return "unknown"
	}
	resp := string(buf[5:])
	if idx := strings.Index(resp, "\x00"); idx != -1 {
		return resp[:idx]
	}
	return "unknown"
}

func mysqlNativePassword(password string, salt []byte) []byte {
	if password == "" {
		return nil
	}
	hash1 := md5Sum([]byte(password))
	hash2 := md5Sum(hash1)
	combined := append(salt, hash2...)
	hash3 := md5Sum(combined)

	result := make([]byte, len(hash1))
	for i := range hash1 {
		result[i] = hash1[i] ^ hash3[i]
	}
	return result
}

func md5Sum(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}

func buildMySQLAuthPacket(user string, authResp []byte) []byte {
	payload := make([]byte, 0, 128)

	capFlags := uint32(0x0003a685)
	maxPktSize := uint32(16777216)

	capBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(capBuf, capFlags)
	payload = append(payload, capBuf...)

	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, maxPktSize)
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

func checkPostgres(ctx context.Context, host string, port int, cred credential) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	startupMsg := buildPgStartup(cred.Username)
	if _, err = conn.Write(startupMsg); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		return false, ""
	}

	if buf[0] != 'R' {
		return false, ""
	}

	authType := binary.BigEndian.Uint32(buf[5:9])

	switch authType {
	case 0:
		return true, fmt.Sprintf("PostgreSQL trust auth user=%s", cred.Username)

	case 3:
		pwMsg := buildPgPasswordMessage(cred.Password)
		if _, err = conn.Write(pwMsg); err != nil {
			return false, ""
		}

	case 5:
		if n < 13 {
			return false, ""
		}
		salt := buf[9:13]
		hash := pgMD5Password(cred.Username, cred.Password, salt)
		pwMsg := buildPgPasswordMessage(hash)
		if _, err = conn.Write(pwMsg); err != nil {
			return false, ""
		}

	default:
		return false, ""
	}

	n, err = conn.Read(buf)
	if err != nil || n < 1 {
		return false, ""
	}

	if buf[0] == 'R' && n >= 9 && binary.BigEndian.Uint32(buf[5:9]) == 0 {
		return true, fmt.Sprintf("PostgreSQL auth OK user=%s", cred.Username)
	}
	return false, ""
}

func pgMD5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := fmt.Sprintf("%x", inner)
	outer := md5.Sum(append([]byte(innerHex), salt...))
	return fmt.Sprintf("md5%x", outer)
}

func buildPgPasswordMessage(password string) []byte {
	msgLen := 4 + len(password) + 1
	msg := make([]byte, 1+msgLen)
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:5], uint32(msgLen))
	copy(msg[5:], password)
	return msg
}

func checkRedis(ctx context.Context, host string, port int, cred credential) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if cred.Password != "" {
		_, _ = fmt.Fprintf(conn, "AUTH %s\r\n", cred.Password)
		body, _ := readRedisResp(conn, 1024)
		if strings.Contains(body, "+OK") {
			return true, strings.TrimSpace(body)
		}
		return false, ""
	}

	_, _ = fmt.Fprintf(conn, "PING\r\n")
	body, _ := readRedisResp(conn, 1024)
	if strings.Contains(body, "+PONG") {
		return true, "PING → " + strings.TrimSpace(body)
	}
	_, _ = fmt.Fprintf(conn, "INFO server\r\n")
	info, _ := readRedisResp(conn, 4096)
	if strings.Contains(info, "redis_version") {
		snippet := info
		if len(snippet) > 400 {
			snippet = snippet[:400] + "..."
		}
		return true, "INFO → " + strings.TrimSpace(snippet)
	}
	return false, ""
}

func redisAuthOK(conn net.Conn) bool {
	body, _ := readRedisResp(conn, 1024)
	return strings.Contains(body, "+OK")
}

func redisRespOK(conn net.Conn) bool {
	body, _ := readRedisResp(conn, 1024)
	return strings.Contains(body, "+PONG") || strings.Contains(body, "+OK")
}

func readRedisResp(conn net.Conn, max int) (string, error) {
	buf := make([]byte, max)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func checkMongo(ctx context.Context, host string, port int, cred credential) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, ""
	}
	conn.Close()
	return false, ""
}

func buildPgStartup(user string) []byte {
	params := fmt.Sprintf("user\x00%s\x00database\x00%s\x00\x00", user, user)
	msgLen := 4 + 4 + len(params)
	msg := make([]byte, msgLen)

	msg[0] = byte(msgLen >> 24)
	msg[1] = byte(msgLen >> 16)
	msg[2] = byte(msgLen >> 8)
	msg[3] = byte(msgLen)

	// Protocol version 3.0
	msg[4] = 0
	msg[5] = 3
	msg[6] = 0
	msg[7] = 0

	copy(msg[8:], params)
	return msg
}

func weakPassFindingTitle(target *core.Target, c credential) string {
	if target.Port == 6379 && c.Password == "" {
		return fmt.Sprintf("Redis 未授权访问 - %s:%d", target.Host, target.Port)
	}
	return fmt.Sprintf("弱口令 - %s:%d", target.Host, target.Port)
}

func weakPassFindingDesc(target *core.Target, c credential) string {
	svc := serviceByPort(target.Port)
	if target.Port == 6379 && c.Password == "" {
		return fmt.Sprintf("服务 %s 允许无密码或未授权访问（PING/INFO 可连通）", svc)
	}
	return fmt.Sprintf("服务 %s 存在弱口令 %s/%s", svc, c.Username, weakPassPasswordLabel(c.Password))
}

func weakPassPasswordLabel(pwd string) string {
	if pwd == "" {
		return "(空)"
	}
	return pwd
}

func serviceByPort(port int) string {
	m := map[int]string{
		21: "FTP", 22: "SSH", 3306: "MySQL",
		5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	}
	if s, ok := m[port]; ok {
		return s
	}
	return "Unknown"
}
