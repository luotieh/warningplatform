package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"
)

type ConfigCheckModule struct {
	timeout time.Duration
}

func NewConfigCheckModule(timeout time.Duration) *ConfigCheckModule {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ConfigCheckModule{timeout: timeout}
}

func (m *ConfigCheckModule) ID() string       { return "config-check" }
func (m *ConfigCheckModule) Name() string     { return "Configuration Check" }
func (m *ConfigCheckModule) Category() string { return "config" }

func (m *ConfigCheckModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		findings := m.checkTarget(ctx, target)
		result.Findings = append(result.Findings, findings...)
	}

	result.Duration = time.Since(start)
	slog.Info("[Config-Check] 检查完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *ConfigCheckModule) checkTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	if target.Port > 0 {
		findings = append(findings, m.checkWeakCredentials(ctx, target)...)
	}

	if target.Port == 443 || target.Protocol == "https" {
		findings = append(findings, m.checkTLSConfig(ctx, target)...)
	}

	if target.Service != "" {
		findings = append(findings, m.checkServiceConfig(ctx, target)...)
	}

	return findings
}

func (m *ConfigCheckModule) checkWeakCredentials(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	weakServices := map[string]struct {
		defaultUser string
		defaultPass string
		checkFunc   func(ctx context.Context, host string, port int, user, pass string) bool
	}{
		"mysql": {
			"root",
			"",
			checkMySQL,
		},
		"redis": {
			"",
			"",
			checkRedis,
		},
		"mongodb": {
			"admin",
			"admin",
			checkMongo,
		},
		"postgresql": {
			"postgres",
			"postgres",
			checkPostgreSQL,
		},
	}

	service := strings.ToLower(target.Service)
	if info, ok := weakServices[service]; ok {
		if info.checkFunc(ctx, target.Host, target.Port, info.defaultUser, info.defaultPass) {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "weak_credential",
				Title:       fmt.Sprintf("Weak Credential: %s", service),
				Description: fmt.Sprintf("%s service is accessible with default/weak credentials", service),
				Severity:    "critical",
				Confidence:  95,
				Evidence: fmt.Sprintf("Successfully connected to %s:%d with user='%s', pass='%s'",
					target.Host, target.Port, info.defaultUser, info.defaultPass),
				Timestamp:   time.Now(),
				Remediation: fmt.Sprintf("Change the default password for %s and restrict network access", service),
			})
		}
	}

	return findings
}

func (m *ConfigCheckModule) checkTLSConfig(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	host := target.Host
	if host == "" {
		host = target.IP
	}
	if host == "" {
		return findings
	}

	port := target.Port
	if port == 0 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := net.Dialer{Timeout: m.timeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if state.Version < tls.VersionTLS12 {
		findings = append(findings, &Finding{
			Target: target,
			Type:   "tls_config",
			Title:  "Weak TLS Version",
			Description: fmt.Sprintf("Server is using TLS %d.%d, which is below the recommended TLS 1.2",
				state.Version>>8, state.Version&0xFF),
			Severity:    "high",
			Confidence:  90,
			Evidence:    fmt.Sprintf("TLS Version: %d", state.Version),
			Timestamp:   time.Now(),
			Remediation: "Configure server to use TLS 1.2 or higher",
		})
	}

	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	for _, weak := range weakCiphers {
		if state.CipherSuite == weak {
			findings = append(findings, &Finding{
				Target:      target,
				Type:        "tls_config",
				Title:       "Weak TLS Cipher Suite",
				Description: "Server is using a weak TLS cipher suite",
				Severity:    "medium",
				Confidence:  85,
				Evidence:    fmt.Sprintf("Cipher Suite: %d", state.CipherSuite),
				Timestamp:   time.Now(),
				Remediation: "Configure server to use strong cipher suites (AES-GCM, ChaCha20)",
			})
			break
		}
	}

	return findings
}

func (m *ConfigCheckModule) checkServiceConfig(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	service := strings.ToLower(target.Service)

	switch service {
	case "ssh":
		findings = append(findings, m.checkSSHConfig(ctx, target)...)
	case "ftp":
		findings = append(findings, m.checkFTPConfig(ctx, target)...)
	case "redis":
		findings = append(findings, m.checkRedisConfig(ctx, target)...)
	}

	return findings
}

func (m *ConfigCheckModule) checkSSHConfig(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	dialer := net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target.Host, target.Port))
	if err != nil {
		return findings
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return findings
	}

	banner := string(buf[:n])

	if strings.Contains(banner, "SSH-1") {
		findings = append(findings, &Finding{
			Target:      target,
			Type:        "ssh_config",
			Title:       "SSH Protocol v1 Enabled",
			Description: "SSH server supports protocol version 1, which has known vulnerabilities",
			Severity:    "high",
			Confidence:  90,
			Evidence:    fmt.Sprintf("SSH Banner: %s", strings.TrimSpace(banner)),
			Timestamp:   time.Now(),
			Remediation: "Disable SSH protocol v1 and only allow SSH v2",
		})
	}

	return findings
}

func (m *ConfigCheckModule) checkFTPConfig(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	dialer := net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target.Host, target.Port))
	if err != nil {
		return findings
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return findings
	}

	banner := string(buf[:n])

	if strings.Contains(strings.ToLower(banner), "anonymous") {
		findings = append(findings, &Finding{
			Target:      target,
			Type:        "ftp_config",
			Title:       "FTP Anonymous Access Enabled",
			Description: "FTP server allows anonymous access",
			Severity:    "medium",
			Confidence:  70,
			Evidence:    fmt.Sprintf("FTP Banner: %s", strings.TrimSpace(banner)),
			Timestamp:   time.Now(),
			Remediation: "Disable anonymous FTP access",
		})
	}

	return findings
}

func (m *ConfigCheckModule) checkRedisConfig(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	dialer := net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", target.Host, target.Port))
	if err != nil {
		return findings
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(m.timeout))
	_, err = conn.Write([]byte("INFO server\r\n"))
	if err != nil {
		return findings
	}

	conn.SetReadDeadline(time.Now().Add(m.timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return findings
	}

	response := string(buf[:n])

	if strings.Contains(response, "redis_version") && !strings.Contains(response, "NOAUTH") {
		findings = append(findings, &Finding{
			Target:      target,
			Type:        "redis_config",
			Title:       "Redis No Authentication",
			Description: "Redis server is accessible without authentication",
			Severity:    "critical",
			Confidence:  95,
			Evidence:    "Redis responded to INFO command without authentication",
			Timestamp:   time.Now(),
			Remediation: "Configure Redis requirepass and bind to localhost only",
		})
	}

	return findings
}

func checkMySQL(ctx context.Context, host string, port int, user, pass string) bool {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return false
	}

	if buf[4] == 0xFF {
		return false
	}

	return true
}

func checkRedis(ctx context.Context, host string, port int, user, pass string) bool {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	return strings.Contains(string(buf[:n]), "+PONG")
}

func checkMongo(ctx context.Context, host string, port int, user, pass string) bool {
	return false
}

func checkPostgreSQL(ctx context.Context, host string, port int, user, pass string) bool {
	return false
}
