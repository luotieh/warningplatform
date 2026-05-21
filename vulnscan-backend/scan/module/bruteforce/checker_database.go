package bruteforce

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ─── MySQL ──────────────────────────────────────────────────────────────────

type MySQLChecker struct{}

func (c *MySQLChecker) Name() string        { return "MySQL" }
func (c *MySQLChecker) DefaultPort() int    { return 3306 }
func (c *MySQLChecker) NeedsUsername() bool { return true }
func (c *MySQLChecker) MatchService(svc string, port int) bool {
	return (svc != "" && strings.Contains(svc, "mysql")) || port == 3306 || port == 3307
}
func (c *MySQLChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false, ""
	}

	if buf[4] != 0x0a {
		return false, ""
	}

	verEnd := 5
	for verEnd < n && buf[verEnd] != 0 {
		verEnd++
	}
	version := string(buf[5:verEnd])
	if !strings.Contains(strings.ToLower(version), "mysql") &&
		!strings.Contains(strings.ToLower(version), "mariadb") {
		return false, ""
	}

	salt1End := verEnd + 5
	if salt1End+8 > n {
		return false, ""
	}
	salt1 := buf[salt1End : salt1End+8]

	capOffset := salt1End + 8 + 1
	restOffset := capOffset + 18
	if restOffset+12 > n {
		return false, ""
	}
	salt2 := buf[restOffset : restOffset+12]

	salt := append(salt1, salt2...)
	authResp := mysqlNativePassword(pass, salt)
	pkt := buildMySQLAuthPacket(user, authResp)
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
	evidence := fmt.Sprintf("greeting: %s\nauth: OK (user=%s)", version, user)
	return true, evidence
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

// ─── PostgreSQL ─────────────────────────────────────────────────────────────

type PostgresChecker struct{}

func (c *PostgresChecker) Name() string        { return "PostgreSQL" }
func (c *PostgresChecker) DefaultPort() int    { return 5432 }
func (c *PostgresChecker) NeedsUsername() bool { return true }
func (c *PostgresChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "postgres") || strings.Contains(svc, "pgsql") || port == 5432
}
func (c *PostgresChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	startupMsg := buildPgStartup(user)
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
		return true, "PostgreSQL (trust auth)"
	case 3:
		pwMsg := buildPgPasswordMessage(pass)
		conn.Write(pwMsg)
	case 5:
		if n < 13 {
			return false, ""
		}
		salt := buf[9:13]
		hash := pgMD5Password(user, pass, salt)
		pwMsg := buildPgPasswordMessage(hash)
		conn.Write(pwMsg)
	default:
		return false, ""
	}

	n, err = conn.Read(buf)
	if err != nil || n < 1 {
		return false, ""
	}
	return buf[0] == 'R' && n >= 9 && binary.BigEndian.Uint32(buf[5:9]) == 0, "PostgreSQL"
}

func pgMD5Password(user, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := fmt.Sprintf("%x", inner)
	outer := md5.Sum(append([]byte(innerHex), salt...))
	return fmt.Sprintf("md5%x", outer)
}

func buildPgStartup(user string) []byte {
	params := fmt.Sprintf("user\x00%s\x00database\x00%s\x00\x00", user, user)
	msgLen := 4 + 4 + len(params)
	msg := make([]byte, msgLen)
	binary.BigEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.BigEndian.PutUint32(msg[4:8], 196608) // version 3.0
	copy(msg[8:], params)
	return msg
}

func buildPgPasswordMessage(password string) []byte {
	msgLen := 4 + len(password) + 1
	msg := make([]byte, 1+msgLen)
	msg[0] = 'p'
	binary.BigEndian.PutUint32(msg[1:5], uint32(msgLen))
	copy(msg[5:], password)
	return msg
}

// ─── MSSQL ──────────────────────────────────────────────────────────────────

type MSSQLChecker struct{}

func (c *MSSQLChecker) Name() string        { return "MSSQL" }
func (c *MSSQLChecker) DefaultPort() int    { return 1433 }
func (c *MSSQLChecker) NeedsUsername() bool { return true }
func (c *MSSQLChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "mssql") || strings.Contains(svc, "ms-sql") ||
		strings.Contains(svc, "tds") || port == 1433
}
func (c *MSSQLChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	prelogin := buildTDSPrelogin()
	if _, err := conn.Write(prelogin); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return false, ""
	}

	if buf[0] != 0x04 {
		return false, ""
	}

	loginPkt := buildTDSLogin7(host, user, pass)
	if _, err := conn.Write(loginPkt); err != nil {
		return false, ""
	}

	n, err = conn.Read(buf)
	if err != nil || n < 8 {
		return false, ""
	}

	if buf[0] == 0x04 && n > 8 {
		for i := 8; i < n-1; i++ {
			if buf[i] == 0xad {
				return true, "MSSQL"
			}
			if buf[i] == 0xaa {
				return false, "MSSQL (login failed)"
			}
		}
	}

	return false, ""
}

func buildTDSPrelogin() []byte {
	option := []byte{0x00, 0x00, 0x15, 0x00, 0x06}
	term := []byte{0xff}
	preData := append(option, term...)

	version := []byte{0x0e, 0x00, 0x0c, 0x44, 0x00, 0x00}
	preData = append(preData, version...)

	total := 8 + len(preData)
	header := make([]byte, 8)
	header[0] = 0x12
	header[1] = 0x01
	binary.BigEndian.PutUint16(header[2:4], uint16(total))
	header[6] = 0x00
	header[7] = 0x00

	return append(header, preData...)
}

func buildTDSLogin7(server, user, pass string) []byte {
	clientName := utf16le("scanner")
	appName := utf16le("vulnscan")
	serverName := utf16le(server)
	userName := utf16le(user)
	password := tdsEncryptPassword(pass)
	dbName := utf16le("master")
	library := utf16le("go-tds")

	fixedLen := 94
	dataOffset := fixedLen

	offsets := make([]byte, 0, 80)
	addOffset := func(data []byte) {
		off := make([]byte, 4)
		binary.LittleEndian.PutUint16(off[0:2], uint16(dataOffset))
		binary.LittleEndian.PutUint16(off[2:4], uint16(len(data)/2))
		offsets = append(offsets, off...)
		dataOffset += len(data)
	}

	addOffset(clientName)
	addOffset(userName)
	addOffset(password)
	addOffset(appName)
	addOffset(serverName)
	offsets = append(offsets, 0, 0, 0, 0) // unused
	addOffset(library)
	offsets = append(offsets, 0, 0, 0, 0) // locale
	addOffset(dbName)

	fixed := make([]byte, 36)
	binary.LittleEndian.PutUint32(fixed[0:4], uint32(dataOffset))
	binary.LittleEndian.PutUint32(fixed[4:8], 0x71000001) // TDS 7.1
	binary.LittleEndian.PutUint32(fixed[8:12], 4096)      // packet size

	loginBody := append(fixed, offsets...)
	for len(loginBody) < fixedLen {
		loginBody = append(loginBody, 0)
	}

	loginBody = append(loginBody, clientName...)
	loginBody = append(loginBody, userName...)
	loginBody = append(loginBody, password...)
	loginBody = append(loginBody, appName...)
	loginBody = append(loginBody, serverName...)
	loginBody = append(loginBody, library...)
	loginBody = append(loginBody, dbName...)

	binary.LittleEndian.PutUint32(loginBody[0:4], uint32(len(loginBody)))

	total := 8 + len(loginBody)
	header := make([]byte, 8)
	header[0] = 0x10
	header[1] = 0x01
	binary.BigEndian.PutUint16(header[2:4], uint16(total))
	header[6] = 0x00
	header[7] = 0x01

	return append(header, loginBody...)
}

func tdsEncryptPassword(password string) []byte {
	u := utf16le(password)
	for i := range u {
		u[i] = ((u[i] & 0x0f) << 4) | ((u[i] & 0xf0) >> 4)
		u[i] ^= 0xa5
	}
	return u
}

func utf16le(s string) []byte {
	result := make([]byte, 0, len(s)*2)
	for _, r := range s {
		result = append(result, byte(r), byte(r>>8))
	}
	return result
}

// ─── Redis ──────────────────────────────────────────────────────────────────

type RedisChecker struct{}

func (c *RedisChecker) Name() string        { return "Redis" }
func (c *RedisChecker) DefaultPort() int    { return 6379 }
func (c *RedisChecker) NeedsUsername() bool { return false }
func (c *RedisChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "redis") || port == 6379
}
func (c *RedisChecker) Check(ctx context.Context, host string, port int, _, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	reader := bufio.NewReader(conn)

	if pass == "" {
		fmt.Fprintf(conn, "PING\r\n")
		resp, _ := reader.ReadString('\n')
		if strings.Contains(resp, "+PONG") {
			fmt.Fprintf(conn, "INFO server\r\n")
			info, _ := readRedisInfoSnippet(reader)
			return true, "Redis 未授权访问 " + strings.TrimSpace(info)
		}
		if strings.Contains(resp, "-NOAUTH") || strings.Contains(strings.ToUpper(resp), "NOAUTH") {
			fmt.Fprintf(conn, "INFO server\r\n")
			info, _ := readRedisInfoSnippet(reader)
			if strings.Contains(info, "redis_version") {
				return true, "Redis 未授权访问(INFO) " + strings.TrimSpace(info)
			}
		}
		return false, ""
	}

	fmt.Fprintf(conn, "AUTH %s\r\n", pass)
	resp, _ := reader.ReadString('\n')
	if strings.Contains(resp, "+OK") {
		fmt.Fprintf(conn, "INFO server\r\n")
		info, _ := reader.ReadString('\n')
		return true, "Redis " + strings.TrimSpace(info)
	}
	return false, ""
}

func readRedisInfoSnippet(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		b.WriteString(line)
		if strings.Contains(line, "redis_version") {
			break
		}
	}
	return b.String(), nil
}

// ─── MongoDB ────────────────────────────────────────────────────────────────

type MongoChecker struct{}

func (c *MongoChecker) Name() string        { return "MongoDB" }
func (c *MongoChecker) DefaultPort() int    { return 27017 }
func (c *MongoChecker) NeedsUsername() bool { return false }
func (c *MongoChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "mongo") || port == 27017
}
func (c *MongoChecker) Check(ctx context.Context, host string, port int, _, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	isMasterCmd := buildMongoIsMaster()
	if _, err := conn.Write(isMasterCmd); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 36 {
		return false, ""
	}

	if n > 36 && strings.Contains(string(buf[36:n]), "ismaster") {
		return true, "MongoDB (无认证)"
	}

	return false, ""
}

func buildMongoIsMaster() []byte {
	doc := []byte{
		0x10, // int32 type
	}
	key := append([]byte("isMaster"), 0)
	doc = append(doc, key...)
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, 1)
	doc = append(doc, val...)
	doc = append(doc, 0)

	docLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(docLen, uint32(4+len(doc)))
	bsonDoc := append(docLen, doc...)

	sections := append([]byte{0}, bsonDoc...)

	msgLen := 4 + 4 + 4 + 4 + 4 + len(sections)
	msg := make([]byte, msgLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint32(msg[4:8], 1)      // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)     // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], 2013) // OP_MSG
	binary.LittleEndian.PutUint32(msg[16:20], 0)    // flagBits
	copy(msg[20:], sections)

	return msg
}

// ─── Memcached ──────────────────────────────────────────────────────────────

type MemcachedChecker struct{}

func (c *MemcachedChecker) Name() string        { return "Memcached" }
func (c *MemcachedChecker) DefaultPort() int    { return 11211 }
func (c *MemcachedChecker) NeedsUsername() bool { return false }
func (c *MemcachedChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "memcache") || port == 11211
}
func (c *MemcachedChecker) Check(ctx context.Context, host string, port int, _, _ string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	fmt.Fprintf(conn, "version\r\n")
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, ""
	}

	if strings.HasPrefix(resp, "VERSION") {
		return true, "Memcached (无认证) " + strings.TrimSpace(resp)
	}
	return false, ""
}
