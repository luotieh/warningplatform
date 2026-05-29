package orchestrate

import (
	"vulnscan-backend/scan/core"

	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
)

const defaultMaxDedupEntries = 500000

// hostLevelTypes 主机级别的发现类型，去重时不应包含端口号
// 这些发现本质上是关于 IP/域名 而非具体服务的，同一 IP/域名 的不同端口应视为重复
var hostLevelTypes = map[string]bool{
	"ip_attribution":         true, // IP归属
	"real_ip":                true, // 真实IP
	"asn":                    true, // ASN
	"organization":           true, // 组织
	"domain":                 true, // 域名
	"ip_range":               true, // IP段
	"internal_ip_leak":       true, // 内网IP泄露
	"dns_multi_ip":           true, // DNS多IP
	"dns_cname":              true, // DNS CNAME
	"dns_nameservers":        true, // DNS域名服务器
	"cdn_detected":           true, // CDN检测
	"load_balancer_detected": true, // 负载均衡检测
	"reverse_dns":            true, // 反向DNS
	"traceroute":             true, // 路由追踪
	"network_gateway":        true, // 网络网关
	"subdomain":              true, // 子域名
	"waf":                    true, // WAF检测
}

type FindingDeduplicator struct {
	mu         sync.RWMutex
	seen       map[string]struct{}
	order      []string
	crossTask  bool
	maxEntries int
}

func NewFindingDeduplicator(crossTask bool) *FindingDeduplicator {
	return &FindingDeduplicator{
		seen:       make(map[string]struct{}),
		order:      make([]string, 0, 1024),
		crossTask:  crossTask,
		maxEntries: defaultMaxDedupEntries,
	}
}

func (d *FindingDeduplicator) IsDuplicate(taskID string, f *core.Finding) bool {
	fp := d.Fingerprint(taskID, f)
	d.mu.RLock()
	_, exists := d.seen[fp]
	d.mu.RUnlock()
	if exists {
		return true
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists = d.seen[fp]; exists {
		return true
	}
	if len(d.seen) >= d.maxEntries {
		d.evictOldest()
	}
	d.seen[fp] = struct{}{}
	d.order = append(d.order, fp)
	return false
}

func (d *FindingDeduplicator) evictOldest() {
	evictCount := len(d.order) / 4
	if evictCount == 0 {
		evictCount = 1
	}
	if evictCount > len(d.order) {
		evictCount = len(d.order)
	}
	for i := 0; i < evictCount; i++ {
		delete(d.seen, d.order[i])
	}
	remaining := len(d.order) - evictCount
	copy(d.order, d.order[evictCount:])
	d.order = d.order[:remaining]
}

func (d *FindingDeduplicator) Fingerprint(taskID string, f *core.Finding) string {
	var parts []string

	if !d.crossTask {
		parts = append(parts, taskID)
	}

	isHostLevel := hostLevelTypes[f.Type]

	if f.Target != nil {
		parts = append(parts, f.Target.Host, f.Target.IP)
		if !isHostLevel {
			parts = append(parts, fmt.Sprintf("%d", f.Target.Port))
		}
	}
	parts = append(parts, f.ModuleID, f.Type, f.Title)

	if f.Data != nil {
		if param, ok := f.Data["param"]; ok {
			parts = append(parts, "p:"+param)
		}
		if via, ok := f.Data["inject_via"]; ok {
			parts = append(parts, "iv:"+via)
		}
	}

	raw := strings.Join(parts, "|")
	h := fnv.New128a()
	h.Write([]byte(raw))
	sum := h.Sum(nil)
	hi := binary.BigEndian.Uint64(sum[:8])
	lo := binary.BigEndian.Uint64(sum[8:])
	return fmt.Sprintf("%016x%016x", hi, lo)
}

func (d *FindingDeduplicator) DeduplicateFindings(taskID string, findings []*core.Finding) []*core.Finding {
	unique := make([]*core.Finding, 0, len(findings))
	for _, f := range findings {
		if !d.IsDuplicate(taskID, f) {
			unique = append(unique, f)
		}
	}
	return unique
}

func (d *FindingDeduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.seen)
}

func (d *FindingDeduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = make(map[string]struct{})
	d.order = d.order[:0]
}
