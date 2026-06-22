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
	ctx, _ := json.Marshal(context)
	level := severityMap[asString(firstNonEmpty(asString(ly["event_level"]), asString(ly["severity"])))]
	if level == "" {
		level = "medium"
	}
	// 标题只用规则描述（规则描述为空时退回事件类型），不再冗余拼接英文类型码
	title := firstNonEmpty(ruleDesc, eventType)
	message := fmt.Sprintf("SIEM告警：检测到 %s 对 %s 发起 %s 攻击，检测方式：%s",
		src, dst, ruleDesc, method)
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
		Observables: []domain.IOC{
			{Type: "ip", Value: src, Role: "source"},
			{Type: "ip", Value: dst, Role: "destination"},
		},
	}
}
