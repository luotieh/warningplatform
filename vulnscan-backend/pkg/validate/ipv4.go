package validate

import (
	"fmt"
	"net"
	"strings"
)

// SplitIPv4List 按常见分隔符拆分多个 IPv4 输入。
func SplitIPv4List(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	replacer := strings.NewReplacer("，", ",", ";", ",", "；", ",", "\n", ",", "\t", ",")
	parts := strings.Split(replacer.Replace(raw), ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsIPv4 判断是否为合法 IPv4（不含 CIDR）。
func IsIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil && !strings.Contains(s, "/")
}

// IPv4List 校验逗号/分号分隔的 IPv4 列表；空字符串通过。
func IPv4List(raw string) error {
	parts := SplitIPv4List(raw)
	if len(parts) == 0 {
		return nil
	}
	for _, p := range parts {
		if !IsIPv4(p) {
			return fmt.Errorf("IPv4 地址格式不正确：%s", p)
		}
	}
	return nil
}
