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
