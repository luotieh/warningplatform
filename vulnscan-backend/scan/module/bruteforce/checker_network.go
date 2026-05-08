package bruteforce

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const dialTimeout = 5 * time.Second
const rwTimeout = 10 * time.Second

func dial(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", addr)
}

// ─── FTP ────────────────────────────────────────────────────────────────────

type FTPChecker struct{}

func (c *FTPChecker) Name() string        { return "FTP" }
func (c *FTPChecker) DefaultPort() int    { return 21 }
func (c *FTPChecker) NeedsUsername() bool { return true }
func (c *FTPChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "ftp") || port == 21
}
func (c *FTPChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		return false, ""
	}

	fmt.Fprintf(conn, "USER %s\r\n", user)
	resp, _ := reader.ReadString('\n')
	if strings.HasPrefix(resp, "230") {
		return true, strings.TrimSpace(banner)
	}
	if !strings.HasPrefix(resp, "331") {
		return false, ""
	}

	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	resp, _ = reader.ReadString('\n')
	return strings.HasPrefix(resp, "230"), strings.TrimSpace(banner)
}

// ─── SSH ────────────────────────────────────────────────────────────────────

type SSHChecker struct{}

func (c *SSHChecker) Name() string        { return "SSH" }
func (c *SSHChecker) DefaultPort() int    { return 22 }
func (c *SSHChecker) NeedsUsername() bool { return true }
func (c *SSHChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "ssh") || port == 22 || port == 2222
}
func (c *SSHChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         dialTimeout,
	}
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false, ""
	}
	banner := string(conn.ServerVersion())
	conn.Close()
	return true, banner
}

// ─── Telnet ─────────────────────────────────────────────────────────────────

type TelnetChecker struct{}

func (c *TelnetChecker) Name() string        { return "Telnet" }
func (c *TelnetChecker) DefaultPort() int    { return 23 }
func (c *TelnetChecker) NeedsUsername() bool { return true }
func (c *TelnetChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "telnet") || port == 23
}
func (c *TelnetChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])

	for strings.Contains(string(buf[:n]), "\xff") && n > 0 {
		n, _ = conn.Read(buf)
		if n > 0 {
			banner += string(buf[:n])
		}
	}

	fmt.Fprintf(conn, "%s\r\n", user)
	time.Sleep(500 * time.Millisecond)
	n, _ = conn.Read(buf)

	fmt.Fprintf(conn, "%s\r\n", pass)
	time.Sleep(1 * time.Second)
	n, _ = conn.Read(buf)
	resp := strings.ToLower(string(buf[:n]))

	failed := strings.Contains(resp, "incorrect") || strings.Contains(resp, "failed") ||
		strings.Contains(resp, "denied") || strings.Contains(resp, "invalid") ||
		strings.Contains(resp, "wrong") || strings.Contains(resp, "error")
	success := strings.Contains(resp, "$") || strings.Contains(resp, "#") ||
		strings.Contains(resp, ">") || strings.Contains(resp, "welcome") ||
		strings.Contains(resp, "last login")

	return !failed && success, truncate(banner, 200)
}

// ─── SMTP ───────────────────────────────────────────────────────────────────

type SMTPChecker struct{}

func (c *SMTPChecker) Name() string        { return "SMTP" }
func (c *SMTPChecker) DefaultPort() int    { return 25 }
func (c *SMTPChecker) NeedsUsername() bool { return true }
func (c *SMTPChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "smtp") || port == 25 || port == 465 || port == 587
}
func (c *SMTPChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	if port == 465 {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			return false, ""
		}
		conn = tlsConn
	}

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		return false, ""
	}

	fmt.Fprintf(conn, "EHLO test\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, ""
		}
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	if port == 587 {
		fmt.Fprintf(conn, "STARTTLS\r\n")
		resp, _ := reader.ReadString('\n')
		if strings.HasPrefix(resp, "220") {
			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			if err := tlsConn.Handshake(); err != nil {
				return false, ""
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			fmt.Fprintf(conn, "EHLO test\r\n")
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				if len(line) >= 4 && line[3] == ' ' {
					break
				}
			}
		}
	}

	fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "334") {
		return false, ""
	}

	fmt.Fprintf(conn, "%s\r\n", base64Encode(user))
	resp, _ = reader.ReadString('\n')
	if !strings.HasPrefix(resp, "334") {
		return false, ""
	}

	fmt.Fprintf(conn, "%s\r\n", base64Encode(pass))
	resp, _ = reader.ReadString('\n')
	return strings.HasPrefix(resp, "235"), strings.TrimSpace(banner)
}

// ─── POP3 ───────────────────────────────────────────────────────────────────

type POP3Checker struct{}

func (c *POP3Checker) Name() string        { return "POP3" }
func (c *POP3Checker) DefaultPort() int    { return 110 }
func (c *POP3Checker) NeedsUsername() bool { return true }
func (c *POP3Checker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "pop") || port == 110 || port == 995
}
func (c *POP3Checker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	var conn net.Conn
	var err error

	if port == 995 {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp",
			net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dial(ctx, host, port)
	}
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if !strings.HasPrefix(banner, "+OK") {
		return false, ""
	}

	fmt.Fprintf(conn, "USER %s\r\n", user)
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "+OK") {
		return false, ""
	}

	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	resp, _ = reader.ReadString('\n')
	return strings.HasPrefix(resp, "+OK"), strings.TrimSpace(banner)
}

// ─── IMAP ───────────────────────────────────────────────────────────────────

type IMAPChecker struct{}

func (c *IMAPChecker) Name() string        { return "IMAP" }
func (c *IMAPChecker) DefaultPort() int    { return 143 }
func (c *IMAPChecker) NeedsUsername() bool { return true }
func (c *IMAPChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "imap") || port == 143 || port == 993
}
func (c *IMAPChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	var conn net.Conn
	var err error

	if port == 993 {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp",
			net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dial(ctx, host, port)
	}
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if !strings.Contains(banner, "OK") {
		return false, ""
	}

	fmt.Fprintf(conn, "a1 LOGIN %s %s\r\n", user, pass)
	resp, _ := reader.ReadString('\n')
	return strings.Contains(resp, "a1 OK"), strings.TrimSpace(banner)
}

// ─── SNMP ───────────────────────────────────────────────────────────────────

type SNMPChecker struct{}

func (c *SNMPChecker) Name() string        { return "SNMP" }
func (c *SNMPChecker) DefaultPort() int    { return 161 }
func (c *SNMPChecker) NeedsUsername() bool { return false }
func (c *SNMPChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "snmp") || port == 161
}
func (c *SNMPChecker) Check(ctx context.Context, host string, port int, _, community string) (bool, string) {
	if community == "" {
		community = "public"
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, dialTimeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	pkt := buildSNMPv2GetRequest(community, "1.3.6.1.2.1.1.1.0")
	if _, err := conn.Write(pkt); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return false, ""
	}

	if buf[0] == 0x30 {
		return true, fmt.Sprintf("SNMP community '%s' accepted", community)
	}
	return false, ""
}

func buildSNMPv2GetRequest(community, oid string) []byte {
	oidBytes := encodeOID(oid)
	varbind := append([]byte{0x30, byte(len(oidBytes) + 4), 0x06, byte(len(oidBytes))}, oidBytes...)
	varbind = append(varbind, 0x05, 0x00)
	varbindList := append([]byte{0x30, byte(len(varbind))}, varbind...)

	reqID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}
	errStatus := []byte{0x02, 0x01, 0x00}
	errIdx := []byte{0x02, 0x01, 0x00}

	pduBody := append(reqID, errStatus...)
	pduBody = append(pduBody, errIdx...)
	pduBody = append(pduBody, varbindList...)

	pdu := append([]byte{0xa0, byte(len(pduBody))}, pduBody...)

	ver := []byte{0x02, 0x01, 0x01}
	comm := append([]byte{0x04, byte(len(community))}, []byte(community)...)

	msg := append(ver, comm...)
	msg = append(msg, pdu...)

	return append([]byte{0x30, byte(len(msg))}, msg...)
}

func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}
	first, _ := strconv.Atoi(parts[0])
	second, _ := strconv.Atoi(parts[1])
	encoded := []byte{byte(first*40 + second)}
	for _, p := range parts[2:] {
		v, _ := strconv.Atoi(p)
		if v < 128 {
			encoded = append(encoded, byte(v))
		} else {
			var tmp []byte
			for v > 0 {
				tmp = append([]byte{byte(v & 0x7f)}, tmp...)
				v >>= 7
			}
			for i := 0; i < len(tmp)-1; i++ {
				tmp[i] |= 0x80
			}
			encoded = append(encoded, tmp...)
		}
	}
	return encoded
}

// ─── VNC ────────────────────────────────────────────────────────────────────

type VNCChecker struct{}

func (c *VNCChecker) Name() string        { return "VNC" }
func (c *VNCChecker) DefaultPort() int    { return 5900 }
func (c *VNCChecker) NeedsUsername() bool { return false }
func (c *VNCChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "vnc") || (port >= 5900 && port <= 5910)
}
func (c *VNCChecker) Check(ctx context.Context, host string, port int, _, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return false, ""
	}
	version := string(buf[:n])
	if !strings.HasPrefix(version, "RFB ") {
		return false, ""
	}

	_, _ = conn.Write(buf[:n])

	n, err = conn.Read(buf)
	if err != nil || n < 1 {
		return false, ""
	}

	numTypes := int(buf[0])
	if numTypes == 0 || n < 1+numTypes {
		return false, ""
	}

	hasNone := false
	for i := 1; i <= numTypes; i++ {
		if buf[i] == 1 {
			hasNone = true
		}
	}

	if hasNone && pass == "" {
		conn.Write([]byte{1})
		n, _ = conn.Read(buf)
		if n >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 {
			return true, "VNC无认证"
		}
	}

	return false, strings.TrimSpace(version)
}

// ─── RDP ────────────────────────────────────────────────────────────────────

type RDPChecker struct{}

func (c *RDPChecker) Name() string        { return "RDP" }
func (c *RDPChecker) DefaultPort() int    { return 3389 }
func (c *RDPChecker) NeedsUsername() bool { return true }
func (c *RDPChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "rdp") || strings.Contains(svc, "ms-wbt") || port == 3389
}
func (c *RDPChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	conn, err := dial(ctx, host, port)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	crReq := buildRDPConnectionRequest()
	if _, err := conn.Write(crReq); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 11 {
		return false, ""
	}

	if buf[0] == 0x03 && buf[11] == 0x02 {
		return false, "RDP NLA required"
	}

	return false, "RDP open"
}

func buildRDPConnectionRequest() []byte {
	cookie := "Cookie: mstshash=scanner\r\n"
	reqLen := 11 + len(cookie) + 8
	pkt := make([]byte, 4+reqLen)
	pkt[0] = 0x03
	pkt[1] = 0x00
	pkt[2] = byte((4 + reqLen) >> 8)
	pkt[3] = byte((4 + reqLen) & 0xff)
	pkt[4] = byte(reqLen - 1)
	pkt[5] = 0xe0
	copy(pkt[11:], cookie)
	off := 11 + len(cookie)
	pkt[off] = 0x01
	pkt[off+1] = 0x00
	pkt[off+2] = 0x08
	pkt[off+3] = 0x00
	pkt[off+4] = 0x03
	pkt[off+5] = 0x00
	pkt[off+6] = 0x00
	pkt[off+7] = 0x00
	return pkt
}

// ─── LDAP ───────────────────────────────────────────────────────────────────

type LDAPChecker struct{}

func (c *LDAPChecker) Name() string        { return "LDAP" }
func (c *LDAPChecker) DefaultPort() int    { return 389 }
func (c *LDAPChecker) NeedsUsername() bool { return true }
func (c *LDAPChecker) MatchService(svc string, port int) bool {
	return strings.Contains(svc, "ldap") || port == 389 || port == 636
}
func (c *LDAPChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, string) {
	var conn net.Conn
	var err error

	if port == 636 {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp",
			net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dial(ctx, host, port)
	}
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(rwTimeout))

	bindReq := buildLDAPSimpleBind(user, pass)
	if _, err := conn.Write(bindReq); err != nil {
		return false, ""
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return false, ""
	}

	resultCode := findLDAPResultCode(buf[:n])
	return resultCode == 0, ""
}

func buildLDAPSimpleBind(dn, password string) []byte {
	version := []byte{0x02, 0x01, 0x03}
	nameBytes := append([]byte{0x04, byte(len(dn))}, []byte(dn)...)
	passBytes := append([]byte{0x80, byte(len(password))}, []byte(password)...)

	bindBody := append(version, nameBytes...)
	bindBody = append(bindBody, passBytes...)

	bindReq := append([]byte{0x60, byte(len(bindBody))}, bindBody...)

	msgID := []byte{0x02, 0x01, 0x01}
	msg := append(msgID, bindReq...)

	return append([]byte{0x30, byte(len(msg))}, msg...)
}

func findLDAPResultCode(data []byte) int {
	for i := 0; i < len(data)-3; i++ {
		if data[i] == 0x61 {
			for j := i + 2; j < len(data)-2; j++ {
				if data[j] == 0x0a && data[j+1] == 0x01 {
					return int(data[j+2])
				}
			}
		}
	}
	return -1
}

func base64Encode(s string) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	src := []byte(s)
	var buf strings.Builder
	for i := 0; i < len(src); i += 3 {
		var b uint32
		remaining := len(src) - i
		for j := 0; j < 3; j++ {
			b <<= 8
			if j < remaining {
				b |= uint32(src[i+j])
			}
		}
		buf.WriteByte(enc[(b>>18)&0x3f])
		buf.WriteByte(enc[(b>>12)&0x3f])
		if remaining > 1 {
			buf.WriteByte(enc[(b>>6)&0x3f])
		} else {
			buf.WriteByte('=')
		}
		if remaining > 2 {
			buf.WriteByte(enc[b&0x3f])
		} else {
			buf.WriteByte('=')
		}
	}
	return buf.String()
}
