package asset

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/validate"
)

var (
	schemeSpacingRE = regexp.MustCompile(`(?i)^(https?)\s*:\s*/\s*`)
	hostPortRE      = regexp.MustCompile(`^([^/:[\s]+):(\d{1,5})(?:/.*)?$`)
	domainLikeRE    = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:/.*)?$`)
	miniProgramRE   = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9/_-]*$`)
)

var urlFirstFamilies = map[string]struct{}{
	"domain_site":      {},
	"official_account": {},
	"mini_program":     {},
	"business_system":  {},
}

// NormalizeAccessAddress 校验并归一化资产访问地址（单目标）。
func NormalizeAccessAddress(raw, assetFamily string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if err := validateAccessAddress(raw); err != nil {
		return "", err
	}
	return normalizeAccessAddressRaw(raw, assetFamily), nil
}

func validateAccessAddress(raw string) error {
	parts := splitAccessAddressParts(raw)
	if len(parts) > 1 {
		return fmt.Errorf("访问地址仅支持填写一个目标；多个请分别登记资产，或使用 IPv4 字段填写多个 IP")
	}
	candidate := fixSchemeSpacing(parts[0])
	if strings.Contains(candidate, "://") && !strings.HasPrefix(strings.ToLower(candidate), "http://") && !strings.HasPrefix(strings.ToLower(candidate), "https://") {
		return fmt.Errorf("仅支持 http:// 或 https:// 协议")
	}
	if strings.HasPrefix(strings.ToLower(candidate), "http://") || strings.HasPrefix(strings.ToLower(candidate), "https://") {
		if _, err := url.ParseRequestURI(fixSchemeSpacing(candidate)); err != nil {
			return fmt.Errorf("URL 格式不正确，请检查协议与主机名")
		}
		return nil
	}
	if isIPv4WithOptionalPort(candidate) {
		return nil
	}
	if looksLikeMiniProgramPath(candidate) {
		return nil
	}
	if domainLikeRE.MatchString(candidate) || hostPortRE.MatchString(candidate) {
		return nil
	}
	return fmt.Errorf("访问地址格式不正确，请填写域名、URL、IP 或 IP:端口")
}

func splitAccessAddressParts(raw string) []string {
	replacer := strings.NewReplacer("，", ",", "；", ";", "\n", ",", "\r", ",", "\t", ",")
	text := replacer.Replace(raw)
	parts := make([]string, 0, 4)
	for _, p := range strings.Split(text, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			return []string{trimmed}
		}
	}
	return parts
}

func fixSchemeSpacing(raw string) string {
	match := schemeSpacingRE.FindStringSubmatch(raw)
	if len(match) < 2 {
		return strings.TrimSpace(raw)
	}
	rest := strings.TrimSpace(raw[len(match[0]):])
	rest = strings.TrimLeft(rest, "/")
	return strings.ToLower(match[1]) + "://" + rest
}

func shouldPreferHTTPScheme(assetFamily, value string) bool {
	if _, ok := urlFirstFamilies[strings.TrimSpace(assetFamily)]; ok {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" || isIPv4WithOptionalPort(value) {
		return false
	}
	if looksLikeMiniProgramPath(value) {
		return false
	}
	return domainLikeRE.MatchString(value) || hostPortRE.MatchString(value)
}

func looksLikeMiniProgramPath(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.Contains(value, " ") {
		return false
	}
	if strings.Contains(value, ".") && domainLikeRE.MatchString(value) {
		return false
	}
	return miniProgramRE.MatchString(value)
}

func isIPv4WithOptionalPort(value string) bool {
	host, portStr, err := net.SplitHostPort(value)
	if err == nil {
		port, perr := strconv.Atoi(portStr)
		if perr != nil || port < 1 || port > 65535 {
			return false
		}
		return validate.IsIPv4(host)
	}
	return validate.IsIPv4(value)
}

func normalizeAccessAddressRaw(raw, assetFamily string) string {
	raw = fixSchemeSpacing(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	preferScheme := shouldPreferHTTPScheme(assetFamily, raw)
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if normalized := normalizeHTTPURL(raw); normalized != "" {
			return normalized
		}
		return raw
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	return normalizeHostLike(raw, preferScheme)
}

func normalizeHTTPURL(raw string) string {
	parsed, err := url.Parse(fixSchemeSpacing(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	out := parsed.String()
	if strings.HasSuffix(out, "/") && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
		out = strings.TrimSuffix(out, "/")
	}
	return out
}

func normalizeHostLike(raw string, preferScheme bool) string {
	if groups := hostPortRE.FindStringSubmatch(raw); len(groups) == 3 {
		host := strings.ToLower(groups[1])
		port := groups[2]
		normalized := host + ":" + port
		if validate.IsIPv4(host) || !preferScheme {
			return normalized
		}
		return "http://" + normalized
	}
	if isIPv4WithOptionalPort(raw) {
		return raw
	}
	if looksLikeMiniProgramPath(raw) {
		return raw
	}
	if domainLikeRE.MatchString(raw) {
		lower := strings.ToLower(raw)
		if preferScheme {
			return "http://" + lower
		}
		return lower
	}
	return raw
}

type derivedNetworkFields struct {
	Domain   string
	IPv4     string
	IPv6     string
	URL      string
	Protocol string
	Port     int
	HasPort  bool
}

func deriveNetworkFieldsFromAccessAddress(address, assetFamily string) derivedNetworkFields {
	address = strings.TrimSpace(address)
	if address == "" {
		return derivedNetworkFields{}
	}
	normalized, err := NormalizeAccessAddress(address, assetFamily)
	if err != nil || normalized == "" {
		return derivedNetworkFields{}
	}
	parsed := parseAccessAddressParts(normalized)
	if parsed == nil {
		return derivedNetworkFields{}
	}
	out := derivedNetworkFields{}
	if parsed.IsMiniProgramPath {
		out.URL = normalized
		return out
	}
	host := strings.TrimSpace(parsed.Host)
	switch {
	case validate.IsIPv4(host):
		out.IPv4 = host
	case isIPv6Host(host):
		out.IPv6 = strings.ToLower(host)
	case host != "":
		out.Domain = strings.ToLower(host)
	}
	if parsed.Port > 0 {
		out.Port = parsed.Port
		out.HasPort = true
	}
	out.Protocol = parsed.Protocol
	if parsed.URL != "" {
		out.URL = parsed.URL
	} else if strings.HasPrefix(strings.ToLower(normalized), "http://") || strings.HasPrefix(strings.ToLower(normalized), "https://") {
		out.URL = normalized
	}
	return out
}

type parsedAccessAddress struct {
	Host              string
	Port              int
	Protocol          string
	URL               string
	IsMiniProgramPath bool
}

func parseAccessAddressParts(normalized string) *parsedAccessAddress {
	normalized = strings.TrimSpace(normalized)
	if normalized == "" {
		return nil
	}
	if looksLikeMiniProgramPath(normalized) {
		return &parsedAccessAddress{IsMiniProgramPath: true, URL: normalized}
	}
	lower := strings.ToLower(normalized)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(normalized)
		if err != nil || parsed.Host == "" {
			return nil
		}
		host := parsed.Hostname()
		port := 0
		if parsed.Port() != "" {
			if p, err := strconv.Atoi(parsed.Port()); err == nil {
				port = p
			}
		}
		return &parsedAccessAddress{
			Host:     host,
			Port:     port,
			Protocol: strings.TrimSuffix(strings.ToLower(parsed.Scheme), ""),
			URL:      normalized,
		}
	}
	if groups := hostPortRE.FindStringSubmatch(normalized); len(groups) == 3 {
		port, _ := strconv.Atoi(groups[2])
		return &parsedAccessAddress{Host: groups[1], Port: port}
	}
	if isIPv4WithOptionalPort(normalized) {
		host, portStr, err := net.SplitHostPort(normalized)
		if err == nil {
			port, _ := strconv.Atoi(portStr)
			return &parsedAccessAddress{Host: host, Port: port}
		}
		return &parsedAccessAddress{Host: normalized}
	}
	if domainLikeRE.MatchString(normalized) {
		host := strings.Split(normalized, "/")[0]
		host = strings.Split(host, ":")[0]
		port := 0
		if idx := strings.Index(normalized, ":"); idx > 0 {
			if p, err := strconv.Atoi(strings.TrimPrefix(strings.Split(normalized, "/")[0][idx+1:], "/")); err == nil {
				port = p
			}
		}
		return &parsedAccessAddress{Host: host, Port: port}
	}
	return nil
}

func isIPv6Host(host string) bool {
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil && strings.Contains(host, ":")
}

// ApplyDerivedNetworkFields 根据访问地址补全空的 domain/ipv4/ipv6/port/url/protocol。
func ApplyDerivedNetworkFields(item *model.Asset) {
	if item == nil {
		return
	}
	derived := deriveNetworkFieldsFromAccessAddress(item.Address, item.AssetFamily)
	if derived.Domain != "" && strings.TrimSpace(item.Domain) == "" {
		item.Domain = derived.Domain
	}
	if derived.IPv4 != "" && strings.TrimSpace(item.IPv4) == "" {
		item.IPv4 = derived.IPv4
	}
	if derived.IPv6 != "" && strings.TrimSpace(item.IPv6) == "" {
		item.IPv6 = derived.IPv6
	}
	if derived.URL != "" && strings.TrimSpace(item.URL) == "" {
		item.URL = derived.URL
	}
	if derived.Protocol != "" && strings.TrimSpace(item.Protocol) == "" {
		item.Protocol = derived.Protocol
	}
	if derived.HasPort && item.Port == 0 {
		item.Port = derived.Port
	}
}

// normalizeAssetAddressFields 保证 address 有值，与列表/编辑展示一致（address 为空时回退 domain/ipv4/ipv6）。
func normalizeAssetAddressFields(item *model.Asset) {
	if item == nil {
		return
	}
	item.Address = strings.TrimSpace(item.Address)
	item.Domain = strings.TrimSpace(item.Domain)
	item.IPv4 = strings.TrimSpace(item.IPv4)
	item.IPv6 = strings.TrimSpace(item.IPv6)
	if item.Address != "" {
		if normalized, err := NormalizeAccessAddress(item.Address, item.AssetFamily); err == nil && normalized != "" {
			item.Address = normalized
		}
		ApplyDerivedNetworkFields(item)
		return
	}
	switch {
	case item.Domain != "":
		item.Address = item.Domain
	case item.IPv4 != "":
		item.Address = item.IPv4
	case item.IPv6 != "":
		item.Address = item.IPv6
	}
}
