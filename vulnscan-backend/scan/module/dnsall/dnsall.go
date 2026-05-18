package dnsall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/core"
)

type DNSEnumerator struct{}

func New() *DNSEnumerator { return &DNSEnumerator{} }

func (m *DNSEnumerator) ID() string       { return "dns_all" }
func (m *DNSEnumerator) Name() string     { return "DNS 全量枚举" }
func (m *DNSEnumerator) Category() string { return "recon" }

func (m *DNSEnumerator) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}

	var mu sync.Mutex

	for _, t := range targets {
		host := strings.TrimSpace(t.Host)
		if host == "" {
			host = strings.TrimSpace(t.IP)
		}
		if host == "" {
			continue
		}

		if ip := net.ParseIP(host); ip != nil {
			ptrs, err := net.DefaultResolver.LookupAddr(ctx, host)
			if err != nil || len(ptrs) == 0 {
				continue
			}
			mu.Lock()
			for _, name := range ptrs {
				val := strings.TrimSuffix(strings.TrimSpace(name), ".")
				if val == "" {
					continue
				}
				result.Findings = append(result.Findings, &core.Finding{
					ModuleID:         m.ID(),
					Target:           t,
					Type:             "dns_record",
					Title:            fmt.Sprintf("[PTR] %s → %s", host, truncate(val, 80)),
					Severity:         "info",
					Confidence:       95,
					ConfidenceReason: "反向 DNS (PTR) 解析",
					Timestamp:        time.Now(),
					Data: map[string]string{
						"record_type": "PTR",
						"name":        host,
						"value":       val,
						"domain":      host,
						"ip":          host,
					},
				})
			}
			mu.Unlock()
			continue
		}

		domain := host
		records := m.enumerateAll(ctx, domain)

		mu.Lock()
		for _, r := range records {
			result.Findings = append(result.Findings, &core.Finding{
				ModuleID:         m.ID(),
				Target:           t,
				Type:             "dns_record",
				Title:            fmt.Sprintf("[%s] %s → %s", r.recordType, r.name, truncate(r.value, 80)),
				Severity:         "info",
				Confidence:       95,
				ConfidenceReason: fmt.Sprintf("DNS %s 查询直接返回，解析器验证", r.recordType),
				Timestamp:        time.Now(),
				Data: map[string]string{
					"record_type": r.recordType,
					"name":        r.name,
					"value":       r.value,
					"domain":      domain,
				},
			})
		}
		mu.Unlock()
	}

	result.Duration = time.Since(start)
	slog.Info("[+] DNS全量枚举完成", "targets", len(targets), "findings", len(result.Findings), "duration", result.Duration)
	return result, nil
}

type dnsRecord struct {
	recordType string
	name       string
	value      string
}

func (m *DNSEnumerator) enumerateAll(ctx context.Context, domain string) []dnsRecord {
	var records []dnsRecord
	var mu sync.Mutex
	var wg sync.WaitGroup

	add := func(rt, name, val string) {
		mu.Lock()
		records = append(records, dnsRecord{recordType: rt, name: name, value: val})
		mu.Unlock()
	}

	// A
	wg.Add(1)
	go func() {
		defer wg.Done()
		ips, _ := net.DefaultResolver.LookupIPAddr(ctx, domain)
		for _, ip := range ips {
			add("A", domain, ip.IP.String())
		}
	}()

	// AAAA (IPv6 included in LookupIPAddr)

	// CNAME
	wg.Add(1)
	go func() {
		defer wg.Done()
		cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
		if err == nil && cname != "" && cname != domain+"." {
			add("CNAME", domain, strings.TrimSuffix(cname, "."))
		}
	}()

	// MX
	wg.Add(1)
	go func() {
		defer wg.Done()
		mxs, _ := net.DefaultResolver.LookupMX(ctx, domain)
		for _, mx := range mxs {
			add("MX", domain, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
		}
	}()

	// NS
	wg.Add(1)
	go func() {
		defer wg.Done()
		nss, _ := net.DefaultResolver.LookupNS(ctx, domain)
		for _, ns := range nss {
			add("NS", domain, strings.TrimSuffix(ns.Host, "."))
		}
	}()

	// TXT (includes SPF, DMARC, etc.)
	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, _ := net.DefaultResolver.LookupTXT(ctx, domain)
		for _, txt := range txts {
			rtype := "TXT"
			if strings.HasPrefix(txt, "v=spf1") {
				rtype = "SPF"
			} else if strings.HasPrefix(txt, "v=DKIM1") {
				rtype = "DKIM"
			}
			add(rtype, domain, txt)
		}
	}()

	// DMARC (_dmarc.domain)
	wg.Add(1)
	go func() {
		defer wg.Done()
		dmarcDomain := "_dmarc." + domain
		txts, _ := net.DefaultResolver.LookupTXT(ctx, dmarcDomain)
		for _, txt := range txts {
			if strings.HasPrefix(txt, "v=DMARC1") {
				add("DMARC", dmarcDomain, txt)
			}
		}
	}()

	// DKIM (common selectors)
	wg.Add(1)
	go func() {
		defer wg.Done()
		selectors := []string{"default", "google", "k1", "k2", "selector1", "selector2", "mail", "dkim", "s1", "s2"}
		for _, sel := range selectors {
			dkimDomain := sel + "._domainkey." + domain
			txts, err := net.DefaultResolver.LookupTXT(ctx, dkimDomain)
			if err != nil || len(txts) == 0 {
				continue
			}
			for _, txt := range txts {
				if strings.Contains(txt, "v=DKIM1") || strings.Contains(txt, "p=") {
					add("DKIM", dkimDomain, truncate(txt, 200))
				}
			}
		}
	}()

	// SRV (common services)
	wg.Add(1)
	go func() {
		defer wg.Done()
		srvPrefixes := []string{
			"_sip._tcp.", "_sip._udp.", "_xmpp-server._tcp.",
			"_xmpp-client._tcp.", "_autodiscover._tcp.",
			"_imap._tcp.", "_imaps._tcp.", "_pop3._tcp.",
			"_submission._tcp.", "_ldap._tcp.",
		}
		for _, prefix := range srvPrefixes {
			srvDomain := prefix + domain
			_, srvs, err := net.DefaultResolver.LookupSRV(ctx, "", "", srvDomain)
			if err != nil || len(srvs) == 0 {
				continue
			}
			for _, srv := range srvs {
				add("SRV", srvDomain, fmt.Sprintf("%d %d %d %s",
					srv.Priority, srv.Weight, srv.Port, strings.TrimSuffix(srv.Target, ".")))
			}
		}
	}()

	// CAA
	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, _ := net.DefaultResolver.LookupTXT(ctx, domain)
		for _, txt := range txts {
			if strings.Contains(txt, "issue") || strings.Contains(txt, "issuewild") || strings.Contains(txt, "iodef") {
				add("CAA", domain, txt)
			}
		}
	}()

	wg.Wait()
	return records
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
