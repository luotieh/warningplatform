package service

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func sortedReportKeys(m map[string]any) []string {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Additional report-only checks address actual failures found in client review.
// They are versioned so previously published documents remain reproducible.
func validateReportBoundaries(text string, refs []string, entries map[string]ReportEvidence) error {
	zeroPayload := false
	for _, id := range refs {
		e := entries[id]
		if (e.SavedDNSRecords > 0 || (e.Finding != nil && e.Finding.Measurements.Values["dns_records"] > 0)) && (strings.Contains(text, "持续通联") || strings.Contains(text, "历史通联") || strings.Contains(text, "历史通信")) {
			return fmt.Errorf("report_dns_association_not_transport_history")
		}
		if e.Finding != nil && e.Finding.Measurements.Values["zero_payload_fraction"] == 1 {
			zeroPayload = true
		}
		if strings.Contains(e.Result, "核验应用载荷总字节=0") {
			zeroPayload = true
		}
	}
	if !zeroPayload && (strings.Contains(text, "无载荷") || strings.Contains(text, "没有载荷")) {
		return fmt.Errorf("report_small_payload_not_zero_payload")
	}
	for _, phrase := range []string{"无跨日持续", "不存在跨日", "不符合持续性恶意", "确认观测数据完整性", "无异常规模", "查询自有域名属正常业务", "自有域名属于正常业务", "正常授权", "无恶意内容", "无异常传输", "TLS握手或心跳", "握手或心跳"} {
		if strings.Contains(text, phrase) {
			return fmt.Errorf("report_unsupported_scope_inference: %s", phrase)
		}
	}
	if strings.Contains(text, "白名单") && !strings.Contains(text, "核验") && !strings.Contains(text, "核对") {
		return fmt.Errorf("report_allowlist_requires_authorization_verification")
	}
	return nil
}

// The immutable document keeps full JSON; prose displays readable field names.
func reportReadableResult(e ReportEvidence) string {
	names := map[string]string{"dns_query": "查询域名", "dns_qtype": "查询类型", "dns_answers": "DNS回答", "sni": "TLS服务名", "tls_sni": "TLS服务名", "ioc": "IOC登记", "ioc_evidence": "情报来源", "ioc_value": "指标对象", "ioc_type": "对象类型", "source": "来源", "confidence": "来源置信标记", "description": "登记说明", "threat_type": "登记类别"}
	var value any
	if json.Unmarshal([]byte(e.Result), &value) != nil {
		return e.Result
	}
	var format func(any) string
	format = func(v any) string {
		switch x := v.(type) {
		case map[string]any:
			parts := []string{}
			// Marshal gives stable key ordering, but iterate through sorted keys here.
			for _, k := range sortedReportKeys(x) {
				label := names[k]
				if label == "" {
					label = k
				}
				parts = append(parts, label+"："+format(x[k]))
			}
			return strings.Join(parts, "；")
		case []any:
			parts := []string{}
			for _, item := range x {
				parts = append(parts, format(item))
			}
			return strings.Join(parts, "、")
		case string:
			return x
		default:
			return fmt.Sprint(x)
		}
	}
	return format(value)
}
