package analyzer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type CrossValidateResult struct {
	DNS        *DNSValidation `json:"dns"`
	TLS        *TLSValidation `json:"tls"`
	Suspicious bool           `json:"suspicious"`
	Score      int            `json:"score"`
	Reasons    []string       `json:"reasons,omitempty"`
}

type DNSValidation struct {
	ResolvedIPs  []string `json:"resolved_ips"`
	HasMultipleA bool     `json:"has_multiple_a"`
	HasCNAME     bool     `json:"has_cname"`
	CNAMETarget  string   `json:"cname_target,omitempty"`
	IsCloudflare bool     `json:"is_cloudflare"`
	IsCDN        bool     `json:"is_cdn"`
	Suspicious   bool     `json:"suspicious"`
	Reason       string   `json:"reason,omitempty"`
}

type TLSValidation struct {
	Valid         bool     `json:"valid"`
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	SANs          []string `json:"sans"`
	DaysLeft      int      `json:"days_left"`
	IsWellKnownCA bool     `json:"is_well_known_ca"`
	ChainComplete bool     `json:"chain_complete"`
	Suspicious    bool     `json:"suspicious"`
	Reason        string   `json:"reason,omitempty"`
}

const crossValidateTimeout = 10 * time.Second

var wellKnownCAs = []string{
	"digicert", "let's encrypt", "comodo", "sectigo", "globalsign",
	"entrust", "godaddy", "verisign", "geotrust", "thawte", "symantec",
	"usertrust", "rapidssl", "amazon", "microsoft", "google trust",
	"isrg", "certum", "actalis", "buypass", "trustasia", "wosign",
	"cfca", "sheca",
}

var cdnProviders = []string{
	"cloudflare", "akamai", "fastly", "cloudfront", "cdn77",
	"stackpath", "keycdn", "azure", "aliyun", "tencent", "baidu",
	"wangsu", "chinacache",
}

func CrossValidateBaseline(ctx context.Context, snap *snapshotData) CrossValidateResult {
	ctx, cancel := context.WithTimeout(ctx, crossValidateTimeout)
	defer cancel()

	result := CrossValidateResult{}
	host := extractHost(snap.URL)
	if host == "" {
		return result
	}

	result.DNS = validateDNS(ctx, host, snap.ResolvedIPs)
	if strings.HasPrefix(snap.URL, "https://") {
		result.TLS = validateTLS(ctx, host, snap)
	}

	if result.DNS != nil && result.DNS.Suspicious {
		result.Suspicious = true
		result.Score += 15
		result.Reasons = append(result.Reasons, result.DNS.Reason)
	}
	if result.TLS != nil && result.TLS.Suspicious {
		result.Suspicious = true
		result.Score += 20
		result.Reasons = append(result.Reasons, result.TLS.Reason)
	}

	return result
}

func validateDNS(ctx context.Context, host string, snapshotIPs []string) *DNSValidation {
	v := &DNSValidation{}

	resolver := &net.Resolver{PreferGo: true}
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		v.Suspicious = true
		v.Reason = fmt.Sprintf("DNS 解析失败: %v", err)
		return v
	}
	v.ResolvedIPs = ips
	v.HasMultipleA = len(ips) > 1

	cname, err := resolver.LookupCNAME(ctx, host)
	if err == nil && cname != "" && cname != host+"." {
		v.HasCNAME = true
		v.CNAMETarget = cname
		lowerCname := strings.ToLower(cname)
		for _, cdn := range cdnProviders {
			if strings.Contains(lowerCname, cdn) {
				v.IsCDN = true
				if cdn == "cloudflare" {
					v.IsCloudflare = true
				}
				break
			}
		}
	}

	if len(snapshotIPs) > 0 && len(ips) > 0 {
		snapshotSet := make(map[string]bool)
		for _, ip := range snapshotIPs {
			snapshotSet[ip] = true
		}
		matched := false
		for _, ip := range ips {
			if snapshotSet[ip] {
				matched = true
				break
			}
		}
		if !matched && !v.IsCDN {
			v.Suspicious = true
			v.Reason = fmt.Sprintf("DNS 解析 IP 与快照 IP 不一致（解析到 %v，快照记录 %v），可能存在 DNS 劫持",
				ips, snapshotIPs)
		}
	}

	return v
}

func validateTLS(ctx context.Context, host string, snap *snapshotData) *TLSValidation {
	v := &TLSValidation{
		Valid:         snap.SSLValid,
		Issuer:        snap.SSLIssuer,
		Subject:       snap.SSLSubject,
		SANs:          snap.SSLSAN,
		DaysLeft:      snap.SSLDaysLeft,
		ChainComplete: snap.SSLChainComplete,
	}

	if snap.SSLIssuer != "" {
		lowerIssuer := strings.ToLower(snap.SSLIssuer)
		for _, ca := range wellKnownCAs {
			if strings.Contains(lowerIssuer, ca) {
				v.IsWellKnownCA = true
				break
			}
		}
	}

	if !snap.SSLValid {
		v.Suspicious = true
		v.Reason = "TLS 证书无效"
		if len(snap.SSLErrors) > 0 {
			v.Reason += "：" + strings.Join(snap.SSLErrors, "; ")
		}
		return v
	}

	if !v.IsWellKnownCA && snap.SSLIssuer != "" {
		v.Suspicious = true
		v.Reason = fmt.Sprintf("TLS 证书签发者 '%s' 不在已知 CA 列表中，可能为自签名或不受信任的证书", snap.SSLIssuer)
		return v
	}

	if !v.ChainComplete {
		v.Suspicious = true
		v.Reason = "TLS 证书链不完整"
		return v
	}

	if snap.SSLDaysLeft < 0 {
		v.Suspicious = true
		v.Reason = "TLS 证书已过期"
		return v
	}

	if snap.SSLSubject != "" && !matchesCertSAN(host, snap.SSLSAN, snap.SSLSubject) {
		v.Suspicious = true
		v.Reason = fmt.Sprintf("TLS 证书 Subject '%s' 与域名 '%s' 不匹配", snap.SSLSubject, host)
		return v
	}

	_ = verifyTLSLive(ctx, host, v)

	return v
}

func verifyTLSLive(ctx context.Context, host string, v *TLSValidation) error {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", host+":443")
	if err != nil {
		if strings.Contains(err.Error(), "certificate") {
			v.Suspicious = true
			v.Reason = fmt.Sprintf("TLS 实时验证失败: %v", err)
		}
		return err
	}
	defer conn.Close()
	return nil
}

func matchesCertSAN(host string, sans []string, subject string) bool {
	if matchWildcard(host, subject) {
		return true
	}
	for _, san := range sans {
		if matchWildcard(host, san) {
			return true
		}
	}
	return false
}

func matchWildcard(host, pattern string) bool {
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) || host == pattern[2:] {
			return true
		}
	}
	return false
}
