package clusterconn

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateMasterURL 校验节点访问主控的完整 API 根地址（须含 scheme 与主机名）。
func ValidateMasterURL(raw string) error {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if u == "" {
		return fmt.Errorf("master_url 不能为空")
	}
	lower := strings.ToLower(u)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("须为完整 HTTP(S) 地址（以 http:// 或 https:// 开头），例如 http://127.0.0.1:8090/api，不能仅为路径 %q", raw)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("URL 格式无效: %w", err)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("缺少主机名，例如 http://127.0.0.1:8090/api")
	}
	return nil
}
