package service

import (
	"bytes"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	"vulnscan-backend/evidence"
)

type ReportPracticalCheck struct {
	Feature  string         `json:"feature"`
	Scope    evidence.Scope `json:"scope"`
	Status   string         `json:"status"`
	Used     int            `json:"used_records"`
	Excluded int            `json:"excluded_records"`
	Reason   string         `json:"reason,omitempty"`
}

// Computes observations from each usable, snapshot-bound field. It never invents
// an empirical baseline, trusts a model verdict, or treats unknown fields as zero.
func collectReportPracticalEvidence(out *SnapshotEvidenceInput) {
	hits := map[string]evidence.Hit{}
	for _, h := range out.Request.Hits {
		hits[h.ID] = h
	}
	bound := func(i evidence.Input, id string, at time.Time) bool {
		h, ok := hits[id]
		return ok && !at.IsZero() && at.Equal(h.OccurredAt) && h.Scope.AssetID == i.Scope.AssetID && h.Scope.DeviceID == i.Scope.DeviceID && (h.Scope == i.Scope || i.Scope.EndpointID == "asset://"+i.Scope.AssetID)
	}
	trusted := func(p evidence.Provenance) bool { return p.Verified && p.Version != "" && len(p.SourceIDs) > 0 }
	add := func(i evidence.Input, feature, name string, used, excluded int, refs []string, metrics any, rule string) {
		status, reason := "measured", ""
		if used == 0 {
			status, reason = "unavailable", "no_usable_snapshot_bound_fields"
		}
		out.Manifest.ReportPracticalChecks = append(out.Manifest.ReportPracticalChecks, ReportPracticalCheck{Feature: feature, Scope: i.Scope, Status: status, Used: used, Excluded: excluded, Reason: reason})
		if used == 0 {
			return
		}
		sort.Strings(refs)
		refs = compactReportRefs(refs)
		raw, _ := json.Marshal(metrics)
		out.Manifest.ReportPractical = append(out.Manifest.ReportPractical, ReportEvidence{Kind: "observation", Name: name, Status: "observed", Scope: i.Scope, Window: reportInputWindow(i), Source: "报告专用字段统计 / 固定快照", SourceIDs: refs, Family: "report_practical:" + feature, Result: fmt.Sprintf("已使用%d条，排除%d条；实际结果=%s；%s", used, excluded, raw, rule), Dependencies: []evidence.Dependency{{Kind: "report_measurement", Version: "report-practical-1.0", SourceIDs: refs}}})
	}
	for _, i := range out.Request.Inputs {
		refs := []string{}
		times := []time.Time{}
		seen := map[string]bool{}
		buckets := map[string]int{}
		for _, h := range out.Request.Hits {
			if h.Scope == i.Scope && !h.OccurredAt.IsZero() && !seen[h.ID] {
				seen[h.ID] = true
				refs = append(refs, h.ID)
				times = append(times, h.OccurredAt)
				buckets[h.OccurredAt.In(reportDayLocation).Truncate(5*time.Minute).Format("2006-01-02 15:04")]++
			}
		}
		if len(times) > 0 {
			sort.Slice(times, func(a, b int) bool { return times[a].Before(times[b]) })
			peak := 0
			for _, count := range buckets {
				if count > peak {
					peak = count
				}
			}
			stats := map[string]any{"五分钟桶次数": buckets, "最高五分钟命中数": peak, "最高桶占保存命中比例": float64(peak) / float64(len(times))}
			if len(times) >= 3 {
				intervals := []float64{}
				for n := 1; n < len(times); n++ {
					intervals = append(intervals, times[n].Sub(times[n-1]).Seconds())
				}
				mean, cv := reportMoments(intervals)
				stats["平均间隔秒"] = mean
				stats["间隔变异系数"] = cv
				stats["间隔样本数"] = len(intervals)
			}
			add(i, "time_distribution", "访问集中时段与间隔分布", len(times), 0, refs, stats, "自动按自然五分钟桶计算；缺长期基线也保留实际集中度与间隔；小样本不称统计显著或严格周期，不把跨桶边界记录强行合并")
		}
		if n := i.Network; n != nil && trusted(n.Provenance) {
			ports, states, mismatch := map[string]int{}, map[string]int{}, map[string]int{}
			refs := []string{}
			used, excluded, parsed := 0, 0, 0
			for _, r := range n.Connections {
				if !bound(i, r.SourceID, r.Time) || r.AssetID != i.Scope.AssetID || r.Destination == "" {
					excluded++
					continue
				}
				used++
				refs = append(refs, r.SourceID)
				ports[fmt.Sprint(r.Port)]++
				if r.TCPState != "" {
					states[r.TCPState]++
				}
				if !r.ProtocolParsed || r.AppProtocol == "" {
					continue
				}
				parsed++
				allowed := reportCommonServicePorts[strings.ToLower(r.AppProtocol)]
				if n.ServicesVerified {
					allowed = nil
					for _, s := range n.Services {
						if strings.EqualFold(s.Protocol, r.AppProtocol) {
							allowed = append(allowed, s.Port)
						}
					}
				}
				if len(allowed) > 0 && !containsReportPort(allowed, r.Port) {
					mismatch[fmt.Sprintf("%s:%d", r.AppProtocol, r.Port)]++
				}
			}
			add(i, "network_fields", "远端服务端口、协议与TCP状态", used, excluded, refs, map[string]any{"远端端点端口次数": ports, "已有TCP状态次数": states, "已解析应用协议记录": parsed, "偏离常见或专用端口": mismatch}, "这里端口属于Scope远端端点，不是资产监听端口；五元组按原始来源与目标解释；协议解析来自实际记录；常见端口是报告默认规则，专用服务配置优先；SYN_SENT不等于超时，单条RST不等于会话失败率")
			if n.ASN != "" || n.Country != "" || n.Reputation != "" {
				add(i, "infrastructure_fields", "目标基础设施已有信息", used, excluded, refs, map[string]string{"ASN": n.ASN, "国家": n.Country, "信誉字段": n.Reputation}, "使用已有属性；不宣称全平台稀有或据地域认定恶意")
			}
		}
		if h := i.HTTP; h != nil && trusted(h.Provenance) {
			refs := []string{}
			used, excluded := 0, 0
			endpoints, uas, odd, credentials := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
			sizes := []float64{}
			sizeRefs := []string{}
			distinct := map[uint64]bool{}
			encoded, longest, fields := 0, 0, 0
			for _, r := range h.Records {
				u, err := url.Parse(r.URL)
				if !bound(i, r.SourceID, r.Time) || err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
					excluded++
					continue
				}
				used++
				refs = append(refs, r.SourceID)
				endpoints[u.Host+u.EscapedPath()]++
				if r.UserAgent != "" {
					uas[r.UserAgent]++
				}
				if u.User != nil || net.ParseIP(u.Hostname()) != nil || strings.HasPrefix(strings.ToLower(u.Hostname()), "0x") {
					odd[u.Host]++
				}
				if !r.Truncated && r.BodyLength != nil {
					sizes = append(sizes, float64(*r.BodyLength))
					sizeRefs = append(sizeRefs, r.SourceID)
					distinct[*r.BodyLength] = true
				}
				for name, value := range r.Fields {
					if evidence.HasCredentialFields(map[string]string{name: ""}) {
						credentials[name]++
					}
					if r.FieldValuesRedacted || strings.Contains(strings.ToLower(name), "token") || strings.EqualFold(name, "authorization") || strings.Count(value, ".") == 2 {
						continue
					}
					fields++
					if reportEncodedLabel(value) != "" {
						encoded++
						if len(value) > longest {
							longest = len(value)
						}
					}
				}
			}
			add(i, "http_structure", "请求端点、UA与登录字段", used, excluded, refs, map[string]any{"端点次数": endpoints, "UA次数": uas, "URL结构特征": odd, "实际凭据字段名次数": credentials}, "不要求品牌、角色或全平台基线；只统计实际字段名，不保存凭据值；重复访问不单独证明C2，登录字段不单独证明钓鱼")
			if fields > 0 {
				add(i, "http_encoding", "实际字段编码结构", used, excluded, refs, map[string]any{"检查字段数": fields, "编码字段数": encoded, "最大编码长度": longest}, "已排除可识别token/JWT字段；统计实际可验证编码，不宣称超出p95")
			}
			if len(sizes) > 0 {
				mean, cv := reportMoments(sizes)
				add(i, "http_size", "请求正文尺寸分布", len(sizes), len(h.Records)-len(sizes), sizeRefs, map[string]any{"平均字节": mean, "尺寸变异系数": cv, "不同尺寸数": len(distinct), "完整尺寸记录": len(sizes)}, "仅使用完整且已绑定记录；小样本展示尺寸，不宣称统计显著或超出业务基线")
			}
		}
		if tls := i.TLS; tls != nil && trusted(tls.Provenance) {
			refs := []string{}
			used, excluded := 0, 0
			expired, future, selfSigned, namesMismatch := 0, 0, 0, 0
			for _, r := range tls.Records {
				if !bound(i, r.SourceID, r.Time) {
					excluded++
					continue
				}
				names, before, after := r.CertificateNames, r.NotBefore, r.NotAfter
				for n, der := range r.CertificatesDER {
					if n != 0 {
						break
					}
					cert, err := x509.ParseCertificate(der)
					if err != nil {
						continue
					}
					before, after, names = cert.NotBefore, cert.NotAfter, cert.DNSNames
					if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
						selfSigned++
					}
				}
				if len(names) == 0 && before.IsZero() && after.IsZero() {
					excluded++
					continue
				}
				used++
				refs = append(refs, r.SourceID)
				if !before.IsZero() && r.Time.Before(before) {
					future++
				}
				if !after.IsZero() && r.Time.After(after) {
					expired++
				}
				if r.SNI != "" && net.ParseIP(r.SNI) == nil && len(names) > 0 {
					cert := x509.Certificate{DNSNames: names}
					if cert.VerifyHostname(r.SNI) != nil {
						namesMismatch++
					}
				}
			}
			add(i, "tls_certificate", "证书有效期及名称检查", used, excluded, refs, map[string]int{"事件时已过期": expired, "事件时尚未生效": future, "自签名签名核验通过": selfSigned, "SNI与证书DNS名称不匹配": namesMismatch}, "不强制签发者名单、信任根或CDN例外名单；这些字段检查不等于证书链不可信或通信恶意")
		}
	}
	for _, i := range out.Request.Inputs {
		h := i.PlatformHistory
		if h == nil {
			h = i.History
		}
		if h == nil || !trusted(h.Provenance) || h.AsOf.IsZero() || h.LookbackStart.IsZero() {
			continue
		}
		refs := []string{}
		used, excluded, dns, transport, sameIOC := 0, 0, 0, 0, 0
		iocs, dates, kinds := map[string]int{}, map[string]int{}, map[string]int{}
		sameDates, sameKinds, transportDates := map[string]int{}, map[string]int{}, map[string]int{}
		transportRefs := []string{}
		seen := map[string]bool{}
		for _, r := range h.Events {
			assetMatches := r.AssetID == i.Scope.AssetID
			for _, asset := range r.AssetIDs {
				assetMatches = assetMatches || asset == i.Scope.AssetID
			}
			if !assetMatches || r.ID == "" || r.ID == out.Request.EventID || seen[r.ID] || r.Time.Before(h.LookbackStart) || !r.Time.Before(h.AsOf) {
				excluded++
				continue
			}
			seen[r.ID] = true
			used++
			refs = append(refs, r.ID)
			dates[r.Time.In(reportDayLocation).Format("2006-01-02")]++
			kinds[r.ObservationKind]++
			if r.IOC != "" {
				iocs[r.IOC]++
			}
			if h.IOC != "" && r.IOC == h.IOC {
				sameIOC++
				sameDates[r.Time.In(reportDayLocation).Format("2006-01-02")]++
				sameKinds[r.ObservationKind]++
				if r.ObservationKind == "transport_contact" {
					transportRefs = append(transportRefs, r.ID)
					transportDates[r.Time.In(reportDayLocation).Format("2006-01-02")]++
				}
			}
			if r.ObservationKind == "dns_record" {
				dns++
			}
			if r.ObservationKind == "transport_contact" {
				transport++
			}
		}
		add(i, "history_association", "同资产历史活动与IOC分布", used, excluded, refs, map[string]any{"历史IOC主体": h.IOC, "相同IOC记录数": sameIOC, "相同IOC首记录日期次数": sameDates, "相同IOC记录类别": sameKinds, "历史事件首记录日期次数": dates, "IOC记录次数": iocs, "历史记录类别": kinds, "DNS记录": dns, "传输接触记录": transport, "历史检索完整": h.Complete}, "全部审核状态参与；逐日统计仅用每个历史事件已保存的首记录时间；同资产其他IOC作为背景，不推断同战役；DNS与通联分开；检索不完整时这些次数为已检索下界，不称首次出现")
		if used > 0 {
			out.Manifest.ReportPractical[len(out.Manifest.ReportPractical)-1].SavedDNSRecords = dns
		}
		if len(transportRefs) > 0 {
			add(i, "history_association_transport", "同资产同IOC历史传输接触", len(transportRefs), 0, transportRefs, map[string]any{"IOC": h.IOC, "实际传输接触事件数": len(transportRefs), "事件首记录日期次数": transportDates, "历史检索完整": h.Complete}, "来源仅包含同资产同IOC的传输接触事件，不含DNS关联或其他IOC；每个日期都有实际首记录；仅说明接触复发，不证明持续攻击或攻击成功")
		}
	}
	for _, i := range out.Request.AssetInputs {
		if d := i.DNS; d != nil && trusted(d.Provenance) {
			refs := []string{}
			domains, roots := map[string]int{}, map[string]int{}
			used, excluded, nx, known, encoded, longest := 0, 0, 0, 0, 0, 0
			for _, r := range d.Records {
				root, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(strings.ToLower(r.Domain), "."))
				if !bound(i, r.SourceID, r.Time) || err != nil {
					excluded++
					continue
				}
				used++
				refs = append(refs, r.SourceID)
				domains[r.Domain]++
				roots[root]++
				if r.RCodeKnown {
					known++
					if r.RCode == 3 {
						nx++
					}
				}
				for _, label := range strings.Split(r.Domain, ".") {
					if len(label) > longest {
						longest = len(label)
					}
					if reportEncodedLabel(label) != "" {
						encoded++
					}
				}
			}
			add(i, "dns_fields", "域名分布、长标签与解析返回码", used, excluded, refs, map[string]any{"域名次数": domains, "注册域次数": roots, "最长标签长度": longest, "可验证编码标签数": encoded, "返回码已知记录": known, "其中NXDOMAIN记录": nx}, "无需同域基线；只统计已保存DNS记录，未知返回码不作成功；不将DNS回答等同传输连接，不宣称全量DNS失败率或DGA")
		}
		if n := i.Network; n != nil && trusted(n.Provenance) {
			refs := []string{}
			buckets := map[string]map[string]bool{}
			used, excluded := 0, 0
			for _, r := range n.Connections {
				if !bound(i, r.SourceID, r.Time) || r.AssetID != i.Scope.AssetID || r.Destination == "" {
					excluded++
					continue
				}
				used++
				refs = append(refs, r.SourceID)
				hour := r.Time.In(reportDayLocation).Format("2006-01-02 15:00")
				if buckets[hour] == nil {
					buckets[hour] = map[string]bool{}
				}
				buckets[hour][fmt.Sprintf("%s:%d", r.Destination, r.Port)] = true
			}
			counts := map[string]int{}
			for hour, targets := range buckets {
				counts[hour] = len(targets)
			}
			add(i, "target_fanout", "每小时目标端点数量", used, excluded, refs, counts, "自动按北京时间自然小时分桶，不要求窗口整点对齐或p99；统计已保存记录，小时边界两侧不合并声称突发")
		}
	}
	// Basic grouping uses actual distinct assets and endpoints, not registered roles.
	groups := map[string]map[string]bool{}
	groupRefs := map[string][]string{}
	for _, r := range out.Manifest.ReportObservations {
		h, ok := hits[r.HitID]
		if !ok || h.Scope != r.Scope || !h.OccurredAt.Equal(r.Time) || r.Time.IsZero() || r.Scope.AssetID == "" || strings.HasPrefix(r.Scope.EndpointID, "asset://") {
			continue
		}
		key := r.Scope.EndpointID + " / " + r.Time.In(reportDayLocation).Format("2006-01-02")
		if groups[key] == nil {
			groups[key] = map[string]bool{}
		}
		groups[key][r.Scope.AssetID] = true
		groupRefs[key] = append(groupRefs[key], r.HitID)
	}
	keys := []string{}
	for key, assets := range groups {
		if len(assets) >= 2 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		assets := []string{}
		for asset := range groups[key] {
			assets = append(assets, asset)
		}
		sort.Strings(assets)
		add(evidence.Input{Scope: evidence.Scope{GroupID: "report-observed:" + digest(key)}}, "shared_endpoint", "同日多资产关联同一端点", len(groupRefs[key]), 0, groupRefs[key], map[string]any{"端点与日期": key, "不同资产数": len(assets), "资产": assets}, "两台资产即可展示共同端点；不要求登记群体ID或角色，不推断协同、传播或同战役")
	}
}

func reportInputWindow(i evidence.Input) *evidence.Window {
	if i.Window == nil {
		return nil
	}
	return &evidence.Window{Start: i.Window.Start, End: i.Window.End, Convention: "analysis_half_open"}
}
func compactReportRefs(refs []string) []string {
	out := []string{}
	for _, id := range refs {
		if len(out) == 0 || out[len(out)-1] != id {
			out = append(out, id)
		}
	}
	return out
}
func reportMoments(v []float64) (float64, float64) {
	mean := 0.0
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	if mean == 0 {
		return mean, 0
	}
	variance := 0.0
	for _, x := range v {
		variance += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(variance/float64(len(v))) / mean
}
func reportEncodedLabel(s string) string {
	if len(s) < 8 {
		return ""
	}
	if len(s)%2 == 0 {
		if b, e := hex.DecodeString(s); e == nil && len(b) >= 4 {
			return "hex"
		}
	}
	if b, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s)); e == nil && len(b) >= 4 && strings.EqualFold(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), s) {
		return "base32"
	}
	return ""
}
func containsReportPort(ports []uint16, p uint16) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}
func reportVisibleBrandWords(page string) []string {
	out := []string{}
	lower := strings.ToLower(page)
	for _, brand := range []string{"微信", "支付宝", "中国银行", "工商银行", "Microsoft", "Google", "Apple", "PayPal", "Outlook", "Office 365", "淘宝", "京东"} {
		if strings.Contains(lower, strings.ToLower(brand)) {
			out = append(out, brand)
		}
	}
	return out
}

var reportCommonServicePorts = map[string][]uint16{"http": {80, 8080, 8000}, "https": {443, 8443}, "tls": {443, 8443, 465, 636, 853, 993, 995}, "dns": {53}, "ssh": {22}, "smtp": {25, 465, 587}, "ftp": {21}, "rdp": {3389}, "mysql": {3306}, "redis": {6379}, "stratum": {3333, 4444, 5555}}
