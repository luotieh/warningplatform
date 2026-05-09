package serviceprobe

import (
	"encoding/hex"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// CompiledFingerprint 编译后的指纹（运行时使用）
type CompiledFingerprint struct {
	ID          string
	Name        string
	Service     string
	Protocol    string
	ProbeType   string
	ProbeData   []byte
	MatchType   string
	MatchRegex  *regexp.Regexp
	MatchWord   string
	VersionExpr *regexp.Regexp
	Priority    int
	Ports       map[int]struct{}

	// HTTP 深度识别
	HTTPPaths     []string
	HTTPHeaders   map[string]string
	HTTPMethod    string
	HTTPMatchBody bool

	// TLS 证书分析
	TLSMatchCN       bool
	TLSMatchSAN      bool
	TLSMatchOrg      bool
	TLSMatchIssuer   bool
	TLSMatchExpiry   bool
	TLSMatchSelfSign bool

	// 探测链
	ProbeChainNext string
}

// FingerprintStore 指纹库 — 多层加载: DB > 用户自定义 > 内嵌默认
type FingerprintStore struct {
	mu           sync.RWMutex
	fingerprints []*CompiledFingerprint
	portMap      map[int]string
	db           *gorm.DB
}

func NewFingerprintStore(db *gorm.DB) *FingerprintStore {
	s := &FingerprintStore{
		portMap: make(map[int]string),
		db:      db,
	}
	s.loadDefaults()
	if db != nil {
		s.loadFromDB()
	}
	return s
}

// LookupPort 端口 → 服务名
func (s *FingerprintStore) LookupPort(port int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.portMap[port]
}

// GetProbes 获取所有主动探测指纹（可按端口过滤）
func (s *FingerprintStore) GetProbes(port int) []*CompiledFingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var probes []*CompiledFingerprint
	for _, fp := range s.fingerprints {
		if fp.ProbeType != "active" {
			continue
		}
		if len(fp.Ports) > 0 {
			if _, ok := fp.Ports[port]; !ok {
				continue
			}
		}
		probes = append(probes, fp)
	}
	return probes
}

// GetHTTPProbes 获取 HTTP 深度探测指纹
func (s *FingerprintStore) GetHTTPProbes(port int) []*CompiledFingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var probes []*CompiledFingerprint
	for _, fp := range s.fingerprints {
		if fp.ProbeType != "active" {
			continue
		}
		if len(fp.HTTPPaths) == 0 {
			continue
		}
		if len(fp.Ports) > 0 {
			if _, ok := fp.Ports[port]; !ok {
				continue
			}
		}
		probes = append(probes, fp)
	}
	return probes
}

// GetPassiveRules 获取所有被动识别规则（按优先级排序）
func (s *FingerprintStore) GetPassiveRules(port int) []*CompiledFingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var rules []*CompiledFingerprint
	for _, fp := range s.fingerprints {
		if fp.ProbeType == "active" {
			continue
		}
		if len(fp.Ports) > 0 {
			if _, ok := fp.Ports[port]; !ok {
				continue
			}
		}
		rules = append(rules, fp)
	}
	return rules
}

// MatchBanner 用所有指纹规则匹配一段 Banner 文本
func (s *FingerprintStore) MatchBanner(banner string, port int) (service, version string, matched bool) {
	rules := s.GetPassiveRules(port)
	for _, rule := range rules {
		ok, ver := matchRule(rule, banner)
		if ok {
			return rule.Service, ver, true
		}
	}
	return "", "", false
}

func matchRule(fp *CompiledFingerprint, banner string) (bool, string) {
	switch fp.MatchType {
	case "regex":
		if fp.MatchRegex == nil {
			return false, ""
		}
		if !fp.MatchRegex.MatchString(banner) {
			return false, ""
		}
		version := ""
		if fp.VersionExpr != nil {
			if m := fp.VersionExpr.FindStringSubmatch(banner); len(m) > 1 {
				version = m[1]
			}
		} else if m := fp.MatchRegex.FindStringSubmatch(banner); len(m) > 1 {
			version = m[1]
		}
		return true, version

	case "word":
		if strings.Contains(banner, fp.MatchWord) {
			return true, ""
		}
		return false, ""

	case "hex":
		hexBanner := hex.EncodeToString([]byte(banner))
		if strings.Contains(hexBanner, fp.MatchWord) {
			return true, ""
		}
		return false, ""
	}
	return false, ""
}

// Reload 热重载指纹库
func (s *FingerprintStore) Reload() {
	s.mu.Lock()
	s.fingerprints = nil
	s.portMap = make(map[int]string)
	s.mu.Unlock()

	s.loadDefaults()
	if s.db != nil {
		s.loadFromDB()
	}
	slog.Info("[*] 指纹库已重载", "total", len(s.fingerprints))
}

func (s *FingerprintStore) loadFromDB() {
	if s.db == nil {
		return
	}

	var fps []model.ServiceFingerprint
	if err := s.db.Where("status = ?", model.FingerprintStatusActive).
		Order("priority DESC").Find(&fps).Error; err != nil {
		slog.Warn("[!] 从DB加载指纹失败，使用默认库", "error", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, fp := range fps {
		compiled := compileFingerprint(fp)
		if compiled != nil {
			s.fingerprints = append(s.fingerprints, compiled)
		}
	}

	var portMaps []model.PortServiceMap
	if err := s.db.Where("status = ?", "active").Find(&portMaps).Error; err == nil {
		for _, pm := range portMaps {
			s.portMap[pm.Port] = pm.Service
		}
	}

	sort.Slice(s.fingerprints, func(i, j int) bool {
		return s.fingerprints[i].Priority > s.fingerprints[j].Priority
	})

	slog.Info("[+] 指纹库加载完成",
		"db_fingerprints", len(fps),
		"db_port_maps", len(portMaps),
		"total", len(s.fingerprints),
	)
}

func compileFingerprint(fp model.ServiceFingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		ID:        fp.ID,
		Name:      fp.Name,
		Service:   fp.Service,
		Protocol:  fp.Protocol,
		ProbeType: fp.ProbeType,
		MatchType: fp.MatchType,
		Priority:  fp.Priority,
	}

	if fp.ProbeData != "" {
		compiled.ProbeData = decodeProbeData(fp.ProbeData)
	}

	switch fp.MatchType {
	case "regex":
		re, err := regexp.Compile(fp.MatchRule)
		if err != nil {
			slog.Warn("[!] 指纹正则编译失败", "name", fp.Name, "error", err)
			return nil
		}
		compiled.MatchRegex = re
	case "word", "hex":
		compiled.MatchWord = fp.MatchRule
	}

	if fp.VersionExpr != "" {
		if re, err := regexp.Compile(fp.VersionExpr); err == nil {
			compiled.VersionExpr = re
		}
	}

	if fp.Ports != "" {
		compiled.Ports = parsePorts(fp.Ports)
	}

	if fp.HTTPPaths != "" {
		compiled.HTTPPaths = parsePaths(fp.HTTPPaths)
	}

	if fp.HTTPHeaders != "" {
		compiled.HTTPHeaders = parseHTTPHeaders(fp.HTTPHeaders)
	}

	if fp.HTTPMethod != "" {
		compiled.HTTPMethod = fp.HTTPMethod
	} else {
		compiled.HTTPMethod = "GET"
	}

	compiled.HTTPMatchBody = fp.HTTPMatchBody
	compiled.TLSMatchCN = fp.TLSMatchCN
	compiled.TLSMatchSAN = fp.TLSMatchSAN
	compiled.TLSMatchOrg = fp.TLSMatchOrg
	compiled.TLSMatchIssuer = fp.TLSMatchIssuer
	compiled.TLSMatchExpiry = fp.TLSMatchExpiry
	compiled.TLSMatchSelfSign = fp.TLSMatchSelfSign
	compiled.ProbeChainNext = fp.ProbeChainNext

	return compiled
}

func parsePaths(pathsStr string) []string {
	var paths []string
	for _, p := range strings.Split(pathsStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

func parseHTTPHeaders(headersStr string) map[string]string {
	headers := make(map[string]string)
	pairs := strings.Split(headersStr, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if idx := strings.Index(pair, ":"); idx > 0 {
			key := strings.TrimSpace(pair[:idx])
			value := strings.TrimSpace(pair[idx+1:])
			if key != "" {
				headers[key] = value
			}
		}
	}
	return headers
}

func decodeProbeData(data string) []byte {
	data = strings.ReplaceAll(data, "\\r", "\r")
	data = strings.ReplaceAll(data, "\\n", "\n")
	data = strings.ReplaceAll(data, "\\t", "\t")
	data = strings.ReplaceAll(data, "\\0", "\x00")
	return []byte(data)
}

func parsePorts(portsStr string) map[int]struct{} {
	m := make(map[int]struct{})
	for _, part := range strings.Split(portsStr, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			low, _ := strconv.Atoi(strings.TrimSpace(bounds[0]))
			high, _ := strconv.Atoi(strings.TrimSpace(bounds[1]))
			for p := low; p <= high; p++ {
				m[p] = struct{}{}
			}
		} else {
			p, _ := strconv.Atoi(part)
			if p > 0 {
				m[p] = struct{}{}
			}
		}
	}
	return m
}

// --- 内嵌默认指纹库 ---

func (s *FingerprintStore) loadDefaults() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, fp := range defaultFingerprints() {
		compiled := &CompiledFingerprint{
			Name:      fp.name,
			Service:   fp.service,
			Protocol:  "tcp",
			ProbeType: fp.probeType,
			MatchType: "regex",
			Priority:  fp.priority,
		}
		if fp.probeData != "" {
			compiled.ProbeData = decodeProbeData(fp.probeData)
			compiled.ProbeType = "active"
		}
		if fp.matchRegex != "" {
			if re, err := regexp.Compile(fp.matchRegex); err == nil {
				compiled.MatchRegex = re
			}
		}
		if fp.versionExpr != "" {
			if re, err := regexp.Compile(fp.versionExpr); err == nil {
				compiled.VersionExpr = re
			}
		}
		if fp.ports != "" {
			compiled.Ports = parsePorts(fp.ports)
		}
		if fp.httpPaths != "" {
			compiled.HTTPPaths = parsePaths(fp.httpPaths)
		}
		if fp.httpHeaders != "" {
			compiled.HTTPHeaders = parseHTTPHeaders(fp.httpHeaders)
		}
		if fp.httpMethod != "" {
			compiled.HTTPMethod = fp.httpMethod
		} else {
			compiled.HTTPMethod = "GET"
		}
		compiled.HTTPMatchBody = fp.httpMatchBody
		compiled.TLSMatchCN = fp.tlsMatchCN
		compiled.TLSMatchSAN = fp.tlsMatchSAN
		compiled.TLSMatchOrg = fp.tlsMatchOrg
		compiled.TLSMatchIssuer = fp.tlsMatchIssuer
		compiled.TLSMatchExpiry = fp.tlsMatchExpiry
		compiled.TLSMatchSelfSign = fp.tlsMatchSelfSign
		compiled.ProbeChainNext = fp.probeChainNext
		s.fingerprints = append(s.fingerprints, compiled)
	}

	for port, svc := range defaultPortMap() {
		if _, ok := s.portMap[port]; !ok {
			s.portMap[port] = svc
		}
	}
}
