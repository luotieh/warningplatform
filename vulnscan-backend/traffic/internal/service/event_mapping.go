package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

var severityMap = map[string]string{
	"critical": "high",
	"high":     "high",
	"medium":   "medium",
	"middle":   "medium",
	"low":      "low",
	"极高":       "high",
	"高":        "high",
	"中":        "medium",
	"低":        "low",
}

// Fingerprint 作为「聚合键」：来源IP + 目标IP + 事件类型。
// 不含发生时间——同一来源对同一目标的同类事件，仅时间不同，会被合并为一条，
// 由 ProcessLyEvent 在命中既有指纹时累加次数并保留各次发生时间。
func Fingerprint(event map[string]any) string {
	// 类型做大小写/空白归一，避免同一类型因书写差异产生不同指纹。
	// 注意：生产方必须统一用“类型代码”(如 scan/dns_tun)，不能用中文标签，
	// 否则代码与标签会算出不同指纹、无法合并（前端研判推送已统一发送代码）。
	etype := strings.ToLower(strings.TrimSpace(
		firstNonEmpty(asString(event["event_type"]), asString(event["type"]), asString(event["threat_type"]))))
	raw := fmt.Sprintf("%v|%v|%v",
		strings.TrimSpace(firstNonEmpty(asString(event["src_ip"]), asString(event["threat_source"]))),
		strings.TrimSpace(firstNonEmpty(asString(event["dst_ip"]), asString(event["victim_target"]))),
		etype,
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func MakeIdempotencyKey(ev map[string]any) string {
	if id := asString(ev["event_id"]); id != "" {
		sum := sha256.Sum256([]byte(id))
		return hex.EncodeToString(sum[:])[:32]
	}
	raw := fmt.Sprintf("%v|%v|%v|%v|%v",
		ev["probe_id"], ev["analyser_id"], ev["threat_type"], ev["flow_id"], ev["time"],
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:32]
}

func LyEventToDeepSOC(ly map[string]any) domain.Event {
	// Prefer real packet IPs. ta_node sends threat_source as a detection label
	// ("payload_rule"/"intel_ip"), NOT an attacker IP, so it must not win over
	// src_ip; keep it only as a last-resort fallback.
	src := firstNonEmpty(asString(ly["src_ip"]), asString(ly["threat_source"]))
	dst := firstNonEmpty(asString(ly["dst_ip"]), asString(ly["victim_target"]))
	ruleDesc := firstNonEmpty(asString(ly["rule_desc"]), asString(ly["event_name"]), asString(ly["message"]))
	eventType := firstNonEmpty(asString(ly["event_type"]), asString(ly["type"]), asString(ly["threat_type"]))
	method := firstNonEmpty(asString(ly["method"]), asString(ly["protocol"]))
	// 威胁侧/资产侧语义归属：报文原始方向(src→dst)不代表攻击方向——命中 IOC 的
	// 一侧永远是威胁侧，另一侧为受影响资产（如内网主机外连 C2：dst==IOC 时攻击源
	// 是 IOC 而非内网主机）。判据不足时留空，message/observables 不断言发起方。
	threat, asset := semanticPeers(ly, src, dst)
	lastSeenAt := activityTime(ly)
	occ := lastSeenAt.Format(time.RFC3339Nano)
	occurrences := []any{}
	if occ != "" {
		occurrences = append(occurrences, buildOccurrence(ly))
	}
	context := map[string]any{
		"ly_id":             ly["id"],
		"ta_node_event_id":  ly["event_id"],
		"device_id":         ly["device_id"],
		"event_type":        ly["event_type"],
		"detail_type":       ly["detail_type"],
		"detection_method":  method,
		"occurrence_time":   occ,
		"duration":          ly["duration"],
		"is_active":         ly["is_active"],
		"processing_status": ly["processing_status"],
		"rule_id":           ly["rule_id"],
		"src_ip":            ly["src_ip"],
		"dst_ip":            ly["dst_ip"],
		"src_port":          ly["src_port"],
		"dst_port":          ly["dst_port"],
		"threat_source":     threat,
		"victim_target":     asset,
		"system_ref":        firstNonEmpty(asString(ly["system_ref"]), asString(ly["source"]), "ta_node"),
		// 聚合元数据：发生次数与首/末次时间，后续同类事件合并时累加（见 ProcessLyEvent）。
		// last_seen_at 记录最近一次攻击活动的时刻，用于静默超时收敛判定
		// （now − last_seen_at ≥ 收敛窗口 ⟹ 已收敛，occurrence_count 即最终频次）。
		"occurrence_count": 1,
		"first_time":       occ,
		"last_time":        occ,
		"occurrences":      occurrences,
		"last_seen_at":     lastSeenAt.Format(time.RFC3339),
	}

	// === ta_node schema v1.1 新增辅助信息 ===
	// 透传融合采集节点解析出的应用层证据与派生/情报元数据，供 AI 详细研判使用。
	// 所有字段在 ta_node 侧为 omitempty，缺省即不存在，这里只在存在时写入，避免 context 膨胀。
	putIfPresent(context, "direction", ly["direction"])
	putIfPresent(context, "threat_index", ly["threat_index"])
	putIfPresent(context, "detection_model", ly["model"])
	putIfPresent(context, "evidence_file", ly["evidence_file"])
	if ef := normalizeEvidenceFiles(ly, 0, occ); len(ef) > 0 {
		context["evidence_files"] = ef
	}
	putIfPresent(context, "packet_time_usec", ly["packet_time_usec"])
	putIfPresent(context, "schema_version", ly["schema_version"])
	putIfPresent(context, "sensor_version", ly["sensor_version"])
	putIfPresent(context, "session_summary", ly["session_summary"])
	// 应用层上下文（HTTP/DNS/payload/icmp），ta_node 以嵌套对象 app 下发，整体透传。
	putIfPresent(context, "app", ly["app"])
	// 平铺 dns_query 一并落库：展示层重算归属时与 ingest 输入保持一致。
	putIfPresent(context, "dns_query", ly["dns_query"])
	// 流统计：流首次时间、持续时长、流/包/字节数（派生字段，零成本）。
	// v1.2 新增通联数据量：wire_bytes 为在线字节(含 L2-L4 头)，与 payload 字节(bytes)并存；
	// volume_role 标识本单向流相对命中 IOC 的方向（to_ioc=数据外传 / from_ioc=载荷下载）。
	if flowStats := collectPresent(ly, "first_time", "duration_ms", "flows", "packets", "bytes",
		"wire_bytes", "volume_role"); len(flowStats) > 0 {
		context["flow_stats"] = flowStats
	}
	// 威胁情报命中元数据：类别、来源、标签、描述、过期时间等。
	if ioc := collectPresent(ly, "ioc_type", "ioc_value", "ioc_category", "ioc_id",
		"ioc_source", "ioc_tags", "ioc_description", "ioc_expire_at"); len(ioc) > 0 {
		context["ioc"] = ioc
	}
	if evidence, ok := ly["ioc_evidence"].(map[string]any); ok && len(evidence) > 0 {
		context["ioc_evidence"] = evidence
	}
	putIfPresent(context, "recommended_action", ly["recommended_action"])
	// v1.2 节点侧局部突发计数：同一威胁键(IOC/规则)在该节点窗口内的命中次数，
	// 属于近似分诊提示(local_scope=node)，非全局权威频次——全局频次以管理侧聚合的
	// occurrence_count 为准，两者语义不同，AI 研判时勿混淆或重复计数。
	if burst := collectPresent(ly, "local_hit_count", "local_window_sec",
		"local_first_seen", "local_scope"); len(burst) > 0 {
		context["local_burst"] = burst
	}
	// 量化统计：首次命中即初始化（occurrence_count=1），后续合并见 updateQuantStats。
	initQuantStats(context, ly)

	ctx, _ := json.Marshal(context)
	level := severityMap[asString(firstNonEmpty(asString(ly["event_level"]), asString(ly["severity"])))]
	if level == "" {
		level = "medium"
	}
	// 标题只用规则描述（规则描述为空时退回事件类型），不再冗余拼接英文类型码
	title := firstNonEmpty(ruleDesc, eventType)
	// message 按语义归属措辞：避免"X 对 Y 发起攻击"的方向先验误导 AI 研判。
	var message string
	switch {
	case threat != "" && asset != "":
		message = fmt.Sprintf("SIEM告警：检测到受影响资产 %s 与威胁地址 %s 的通讯（%s），检测方式：%s",
			asset, threat, ruleDesc, method)
	case asset != "":
		message = fmt.Sprintf("SIEM告警：检测到 %s 的可疑通讯（%s，威胁侧待研判），检测方式：%s",
			asset, ruleDesc, method)
	case threat != "":
		message = fmt.Sprintf("SIEM告警：检测到与威胁地址 %s 相关的可疑通讯（%s，受影响资产待研判），检测方式：%s",
			threat, ruleDesc, method)
	default:
		message = fmt.Sprintf("SIEM告警：检测到 %s 与 %s 之间命中规则的可疑通讯（%s，通讯方向待研判），检测方式：%s",
			src, dst, ruleDesc, method)
	}
	observables := []domain.IOC{
		{Type: "ip", Value: src, Role: "source"},
		{Type: "ip", Value: dst, Role: "destination"},
	}
	// role=source/destination 保留报文原始方向（研判回传/指纹用）；
	// 威胁侧/资产侧语义单独标注，供 AI 直接采用，不得互换。
	if threat != "" {
		observables = append(observables, domain.IOC{Type: observableAddrType(threat), Value: threat, Role: "threat_source"})
	}
	if asset != "" {
		observables = append(observables, domain.IOC{Type: "ip", Value: asset, Role: "affected_asset"})
	}
	// 威胁情报命中值（如恶意域名/IP/URL）作为可观察对象补充，供 AI 关联研判。
	if iocVal := asString(ly["ioc_value"]); iocVal != "" {
		observables = append(observables, domain.IOC{
			Type:  firstNonEmpty(asString(ly["ioc_type"]), "indicator"),
			Value: iocVal,
			Role:  "threat_intel",
		})
	}
	return domain.Event{
		EventID:     asString(ly["event_id"]),
		EventName:   title,
		Title:       title,
		Message:     message,
		Severity:    level,
		Source:      "ta_node",
		Category:    "Network Threat",
		Context:     string(ctx),
		EventStatus: "pending",
		Observables: observables,
		LastSeenAt:  &lastSeenAt,
	}
}

// putIfPresent 仅在 v 非空（非 nil、非空字符串）时写入 dst[key]，
// 用于透传 ta_node omitempty 字段，避免在 context 中写入大量 null。
func putIfPresent(dst map[string]any, key string, v any) {
	if v == nil {
		return
	}
	if s, ok := v.(string); ok && strings.TrimSpace(s) == "" {
		return
	}
	dst[key] = v
}

// collectPresent 从 src 中挑出存在且非空的若干键，组成新 map（保持原键名）。
func collectPresent(src map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		putIfPresent(out, k, src[k])
	}
	return out
}

// semanticPeers 判定事件的威胁侧与受影响资产侧（ingest 适配器）。
// 判定逻辑与列表展示层共用 domain.AttributePeers 一份实现，保证
// AI 研判输入的语义标注与列表「攻击源/受害目标」列始终一致。
// 返回空字符串表示无法可靠判定，调用方不得据此断言攻击发起方。
func semanticPeers(ly map[string]any, src, dst string) (threat, asset string) {
	app, _ := ly["app"].(map[string]any)
	return domain.AttributePeers(domain.PeerAttributionInput{
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   toInt(ly["src_port"]),
		DstPort:   toInt(ly["dst_port"]),
		DNSQuery:  firstNonEmpty(asString(app["dns_query"]), asString(ly["dns_query"])),
		IOCType:   asString(ly["ioc_type"]),
		IOCValue:  asString(ly["ioc_value"]),
		Direction: asString(ly["direction"]),
	})
}

// observableAddrType 按可观察值形态给出类型：可解析为 IP 则为 ip，否则按域名处理。
func observableAddrType(v string) string {
	if _, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
		return "ip"
	}
	return "domain"
}
