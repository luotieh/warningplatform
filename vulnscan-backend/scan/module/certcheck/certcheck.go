package certcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type CertChecker struct{}

func New() *CertChecker { return &CertChecker{} }

func (m *CertChecker) ID() string       { return "cert_check" }
func (m *CertChecker) Name() string     { return "TLS/SSL 证书检测" }
func (m *CertChecker) Category() string { return "vuln" }

func (m *CertChecker) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 20)

	for _, t := range targets {
		if !isTLSTarget(t) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *core.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.checkTarget(ctx, target)
			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(t)
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] TLS证书检测完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *CertChecker) checkTarget(ctx context.Context, target *core.Target) []*core.Finding {
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	port := target.Port
	if port <= 0 {
		port = 443
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var findings []*core.Finding

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	for _, version := range weakTLSVersions() {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version.version,
			MaxVersion:         version.version,
		})
		if err != nil {
			continue
		}
		conn.Close()

		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "weak_tls",
			Title:       fmt.Sprintf("支持弱TLS版本: %s", version.name),
			Description: fmt.Sprintf("服务器 %s:%d 支持已废弃的TLS版本 %s，存在降级攻击风险", host, port, version.name),
			Severity:    version.severity,
			Confidence:  95,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"tls_version": version.name,
			},
		})
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return findings
	}

	cert := state.PeerCertificates[0]
	daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)

	if time.Now().After(cert.NotAfter) {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "cert_expired",
			Title:       "SSL证书已过期",
			Description: fmt.Sprintf("证书 %s 已于 %s 过期", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02")),
			Severity:    "high",
			Confidence:  100,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"common_name": cert.Subject.CommonName,
				"expired_at":  cert.NotAfter.Format(time.RFC3339),
				"expires_at":  cert.NotAfter.Format(time.RFC3339),
				"not_before":  cert.NotBefore.Format(time.RFC3339),
				"not_after":   cert.NotAfter.Format(time.RFC3339),
				"issuer":      cert.Issuer.CommonName,
			},
		})
	}

	if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "cert_expiring_soon",
			Title:       fmt.Sprintf("SSL证书即将过期 (%d天)", daysUntilExpiry),
			Description: fmt.Sprintf("证书 %s 将在 %d 天后过期 (%s)", cert.Subject.CommonName, daysUntilExpiry, cert.NotAfter.Format("2006-01-02")),
			Severity:    "medium",
			Confidence:  100,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"common_name": cert.Subject.CommonName,
				"expires_at":  cert.NotAfter.Format(time.RFC3339),
				"not_before":  cert.NotBefore.Format(time.RFC3339),
				"not_after":   cert.NotAfter.Format(time.RFC3339),
				"days_until":  strconv.Itoa(daysUntilExpiry),
				"issuer":      cert.Issuer.CommonName,
			},
		})
	}

	if cert.IsCA {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "self_signed_cert",
			Title:       "使用自签名证书",
			Description: fmt.Sprintf("证书 %s 为自签名证书，可能导致中间人攻击", cert.Subject.CommonName),
			Severity:    "medium",
			Confidence:  90,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"common_name": cert.Subject.CommonName,
				"issuer":      cert.Issuer.CommonName,
			},
		})
	}

	if cert.PublicKeyAlgorithm == x509.RSA {
		if key := cert.PublicKey; key != nil {
			if keySize := certKeySize(cert); keySize > 0 && keySize < 2048 {
				findings = append(findings, &core.Finding{
					ModuleID:    m.ID(),
					Target:      target,
					Type:        "weak_key",
					Title:       fmt.Sprintf("RSA密钥长度不足 (%d bits)", keySize),
					Description: fmt.Sprintf("证书使用 %d 位RSA密钥，建议使用2048位以上", keySize),
					Severity:    "high",
					Confidence:  95,
					Timestamp:   time.Now(),
					Data: map[string]string{
						"key_size":  strconv.Itoa(keySize),
						"algorithm": "RSA",
					},
				})
			}
		}
	}

	if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.MD5WithRSA {
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "weak_signature",
			Title:       fmt.Sprintf("弱签名算法: %s", cert.SignatureAlgorithm.String()),
			Description: fmt.Sprintf("证书使用不安全的签名算法 %s", cert.SignatureAlgorithm.String()),
			Severity:    "high",
			Confidence:  95,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"algorithm": cert.SignatureAlgorithm.String(),
			},
		})
	}

	if f := checkWeakCiphers(state, target, m.ID()); f != nil {
		findings = append(findings, f)
	}

	// 未过期证书：产出基线 cert_info，便于资产富化/报表统一消费（RFC3339 时间字段）。
	if !time.Now().After(cert.NotAfter) {
		daysOut := daysUntilExpiry
		if daysOut < 0 {
			daysOut = 0
		}
		data := map[string]string{
			"common_name": cert.Subject.CommonName,
			"issuer":      cert.Issuer.CommonName,
			"not_before":  cert.NotBefore.Format(time.RFC3339),
			"not_after":   cert.NotAfter.Format(time.RFC3339),
			"expires_at":  cert.NotAfter.Format(time.RFC3339),
			"days_until":  strconv.Itoa(daysOut),
		}
		if len(cert.DNSNames) > 0 {
			data["dns_names"] = strings.Join(cert.DNSNames, ",")
		}
		if cert.Issuer.String() == cert.Subject.String() {
			data["is_self_signed"] = "true"
		} else {
			data["is_self_signed"] = "false"
		}
		findings = append(findings, &core.Finding{
			ModuleID:    m.ID(),
			Target:      target,
			Type:        "cert_info",
			Title:       fmt.Sprintf("TLS 证书: %s (至 %s)", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02")),
			Description: fmt.Sprintf("证书 CN=%s，颁发者=%s，剩余约 %d 天", cert.Subject.CommonName, cert.Issuer.CommonName, daysUntilExpiry),
			Severity:    "info",
			Confidence:  100,
			Timestamp:   time.Now(),
			Data:        data,
		})
	}

	return findings
}

type tlsVersion struct {
	version  uint16
	name     string
	severity string
}

func weakTLSVersions() []tlsVersion {
	return []tlsVersion{
		{version: tls.VersionSSL30, name: "SSLv3", severity: "critical"},
		{version: tls.VersionTLS10, name: "TLS 1.0", severity: "high"},
		{version: tls.VersionTLS11, name: "TLS 1.1", severity: "medium"},
	}
}

func isTLSTarget(t *core.Target) bool {
	if t.URL != "" && strings.HasPrefix(t.URL, "https") {
		return true
	}
	tlsPorts := map[int]bool{
		443: true, 8443: true, 993: true, 995: true,
		465: true, 636: true, 989: true, 990: true,
	}
	return tlsPorts[t.Port]
}

func certKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return pub.Size() * 8
	default:
		return 0
	}
}

func checkWeakCiphers(state tls.ConnectionState, target *core.Target, moduleID string) *core.Finding {
	weakCiphers := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:      "RC4-SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: "3DES-CBC-SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:  "AES128-CBC-SHA",
	}

	if name, ok := weakCiphers[state.CipherSuite]; ok {
		return &core.Finding{
			ModuleID:    moduleID,
			Target:      target,
			Type:        "weak_cipher",
			Title:       fmt.Sprintf("使用弱加密套件: %s", name),
			Description: fmt.Sprintf("服务器协商了不安全的加密套件 %s (0x%04X)", name, state.CipherSuite),
			Severity:    "medium",
			Confidence:  90,
			Timestamp:   time.Now(),
			Data: map[string]string{
				"cipher_suite": name,
				"cipher_id":    fmt.Sprintf("0x%04X", state.CipherSuite),
			},
		}
	}

	return nil
}
