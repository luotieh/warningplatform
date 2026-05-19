package sitemonitor

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"vulnscan-backend/model"
)

// ResolvedEndpoint 监测请求地址与虚拟主机信息。
type ResolvedEndpoint struct {
	RequestURL  string // 实际请求的 URL（IP 目标时为 https://1.2.3.1/path）
	RequestHost string // HTTP Host 头（IP+虚拟主机时必填）
	DisplayURL  string // 展示用完整 URL
}

// ResolvePathTaskURL 根据监测目标与路径任务计算监测 URL。
func ResolvePathTaskURL(target *model.MonitorTarget, path *model.MonitorPathTask) (*ResolvedEndpoint, error) {
	if target == nil || path == nil {
		return nil, fmt.Errorf("target or path task is nil")
	}
	if override := strings.TrimSpace(path.URLOverride); override != "" {
		u, err := url.Parse(override)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid url_override: %s", override)
		}
		host := u.Hostname()
		return &ResolvedEndpoint{
			RequestURL:  override,
			RequestHost: host,
			DisplayURL:  override,
		}, nil
	}
	return resolveFromTargetAndPath(target, strings.TrimSpace(path.Path))
}

// ResolveTargetRootURL 目标根路径 URL（用于爬虫种子、敏感文件探测等）。
func ResolveTargetRootURL(target *model.MonitorTarget) (*ResolvedEndpoint, error) {
	if target == nil {
		return nil, fmt.Errorf("target is nil")
	}
	return resolveFromTargetAndPath(target, "/")
}

func resolveFromTargetAndPath(target *model.MonitorTarget, path string) (*ResolvedEndpoint, error) {
	scheme := strings.TrimSpace(target.DefaultScheme)
	if scheme == "" {
		scheme = "https"
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	tt := strings.ToLower(strings.TrimSpace(target.TargetType))
	val := strings.TrimSpace(target.TargetValue)
	if val == "" {
		return nil, fmt.Errorf("target_value is empty")
	}

	switch tt {
	case model.MonitorTargetTypeIP:
		host := val
		if strings.Contains(host, ":") {
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("invalid ip target: %s", val)
		}
		vhost := strings.TrimSpace(target.VirtualHost)
		if vhost == "" {
			return nil, fmt.Errorf("virtual_host is required for ip target")
		}
		reqURL := fmt.Sprintf("%s://%s%s", scheme, host, path)
		display := fmt.Sprintf("%s://%s%s", scheme, vhost, path)
		return &ResolvedEndpoint{
			RequestURL:  reqURL,
			RequestHost: vhost,
			DisplayURL:  display,
		}, nil
	case model.MonitorTargetTypeDomain:
		domain := strings.TrimPrefix(strings.ToLower(val), "http://")
		domain = strings.TrimPrefix(domain, "https://")
		domain = strings.TrimSuffix(domain, "/")
		if idx := strings.Index(domain, "/"); idx >= 0 {
			domain = domain[:idx]
		}
		if domain == "" {
			return nil, fmt.Errorf("invalid domain target")
		}
		reqURL := fmt.Sprintf("%s://%s%s", scheme, domain, path)
		return &ResolvedEndpoint{
			RequestURL:  reqURL,
			RequestHost: domain,
			DisplayURL:  reqURL,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported target_type: %s", target.TargetType)
	}
}
