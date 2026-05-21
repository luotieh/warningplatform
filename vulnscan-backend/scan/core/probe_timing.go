package core

import (
	"net"
	"strconv"
	"time"
)

// 端口探测默认超时：关闭端口通常立即 RST（<50ms），3s 仅适合高丢包网络。
const (
	DefaultPortConnectTimeout = 800 * time.Millisecond
	MaxPortConnectTimeout     = 2 * time.Second
	MinPortConnectTimeout     = 150 * time.Millisecond
)

// PortConnectTimeout 从模块 config 解析 TCP 连接超时（支持 "800ms"、"1s" 或秒数）。
func PortConnectTimeout(config map[string]interface{}) time.Duration {
	if config == nil {
		return DefaultPortConnectTimeout
	}
	if v, ok := config["timeout"].(string); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return clampPortTimeout(d)
		}
	}
	switch v := config["timeout"].(type) {
	case float64:
		if v > 0 {
			return clampPortTimeout(time.Duration(v * float64(time.Second)))
		}
	case int:
		if v > 0 {
			return clampPortTimeout(time.Duration(v) * time.Second)
		}
	}
	if v, ok := config["timeout_ms"].(float64); ok && v > 0 {
		return clampPortTimeout(time.Duration(v) * time.Millisecond)
	}
	return DefaultPortConnectTimeout
}

// PortConnectTimeoutForScan 按端口规模略微收紧全端口扫描，避免 65535×长超时。
func PortConnectTimeoutForScan(config map[string]interface{}, portCount int) time.Duration {
	base := PortConnectTimeout(config)
	if portCount <= 1000 {
		return base
	}
	if portCount > 10000 {
		if base > 600*time.Millisecond {
			return 600 * time.Millisecond
		}
		return base
	}
	if base > 1*time.Second {
		return 1 * time.Second
	}
	return base
}

// AdjustPortTimeoutByRTT 根据探活 RTT 动态调整（有响应主机用更短等待）。
func AdjustPortTimeoutByRTT(rtt, base time.Duration) time.Duration {
	if rtt <= 0 {
		return base
	}
	dynamic := rtt * 3
	if dynamic < MinPortConnectTimeout {
		dynamic = MinPortConnectTimeout
	}
	if dynamic > base {
		return base
	}
	return dynamic
}

func clampPortTimeout(d time.Duration) time.Duration {
	if d < MinPortConnectTimeout {
		return MinPortConnectTimeout
	}
	if d > MaxPortConnectTimeout {
		return MaxPortConnectTimeout
	}
	return d
}

// CanRawSYNScan 当前进程是否可打开 raw socket 做 SYN 扫描（通常需 root/管理员）。
func CanRawSYNScan() bool {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ParseProbeConcurrency 解析端口扫描并发。
func ParseProbeConcurrency(config map[string]interface{}, defaultVal int) int {
	if config == nil {
		return defaultVal
	}
	if v, ok := config["concurrency"]; ok {
		switch n := v.(type) {
		case float64:
			if int(n) > 0 {
				return int(n)
			}
		case int:
			if n > 0 {
				return n
			}
		case string:
			if i, err := strconv.Atoi(n); err == nil && i > 0 {
				return i
			}
		}
	}
	return defaultVal
}

// MinProbeConcurrencyForPorts 大规模端口扫描时提高自适应降速下限，避免退到 100 并发过慢。
func MinProbeConcurrencyForPorts(portCount int) int {
	switch {
	case portCount > 20000:
		return 800
	case portCount > 5000:
		return 500
	case portCount > 1000:
		return 300
	default:
		return 100
	}
}
