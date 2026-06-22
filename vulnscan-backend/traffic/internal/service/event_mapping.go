package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	occurrences := []any{}
	if occ != "" {
		occurrences = append(occurrences, occ)
	}
	context := map[string]any{
		"ly_id":             ly["id"],
		"ta_node_event_id":  ly["event_id"],
		"device_id":         ly["device_id"],
		"event_type":        ly["event_type"],
		"detail_type":       ly["detail_type"],
		"detection_method":  method,
		"occurrence_time":   ly["occurrence_time"],
		"duration":          ly["duration"],
		"is_active":         ly["is_active"],
		"processing_status": ly["processing_status"],
		"rule_id":           ly["rule_id"],
		"src_ip":            ly["src_ip"],
		"dst_ip":            ly["dst_ip"],
		"src_port":          ly["src_port"],
		"dst_port":          ly["dst_port"],
		"threat_source":     src,
		"victim_target":     dst,
		"system_ref":        firstNonEmpty(asString(ly["system_ref"]), asString(ly["source"]), "ta_node"),
		// 聚合元数据：发生次数与首/末次时间，后续同类事件合并时累加（见 ProcessLyEvent）。
		// last_seen_at 记录服务器最近一次收到该聚合命中的时刻，用于静默超时收敛判定
		// （now − last_seen_at ≥ 收敛窗口 ⟹ 已收敛，occurrence_count 即最终频次）。
		"occurrence_count": 1,
		"first_time":       occ,
		"last_time":        occ,
		"occurrences":      occurrences,
		"last_seen_at":     time.Now().UTC().Format(time.RFC3339),
	}

	// === ta_node schema v1.1 新增辅助信息 ===
	// 透传融合采集节点解析出的应用层证据与派生/情报元数据，供 AI 详细研判使用。
	// 所有字段在 ta_node 侧为 omitempty，缺省即不存在，这里只在存在时写入，避免 context 膨胀。
	putIfPresent(context, "direction", ly["direction"])
	putIfPresent(context, "threat_index", ly["threat_index"])
	putIfPresent(context, "detection_model", ly["model"])
	putIfPresent(context, "evidence_file", ly["evidence_file"])
	putIfPresent(context, "packet_time_usec", ly["packet_time_usec"])
	putIfPresent(context, "schema_version", ly["schema_version"])
	putIfPresent(context, "sensor_version", ly["sensor_version"])
	// 应用层上下文（HTTP/DNS/payload/icmp），ta_node 以嵌套对象 app 下发，整体透传。
	putIfPresent(context, "app", ly["app"])
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
	// v1.2 节点侧局部突发计数：同一威胁键(IOC/规则)在该节点窗口内的命中次数，
	// 属于近似分诊提示(local_scope=node)，非全局权威频次——全局频次以管理侧聚合的
	// occurrence_count 为准，两者语义不同，AI 研判时勿混淆或重复计数。
	if burst := collectPresent(ly, "local_hit_count", "local_window_sec",
		"local_first_seen", "local_scope"); len(burst) > 0 {
		context["local_burst"] = burst
	}

	ctx, _ := json.Marshal(context)
	level := severityMap[asString(firstNonEmpty(asString(ly["event_level"]), asString(ly["severity"])))]
	if level == "" {
		level = "medium"
	}
	// 标题只用规则描述（规则描述为空时退回事件类型），不再冗余拼接英文类型码
	title := firstNonEmpty(ruleDesc, eventType)
	message := fmt.Sprintf("SIEM告警：检测到 %s 对 %s 发起 %s 攻击，检测方式：%s",
		src, dst, ruleDesc, method)
	observables := []domain.IOC{
		{Type: "ip", Value: src, Role: "source"},
		{Type: "ip", Value: dst, Role: "destination"},
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
