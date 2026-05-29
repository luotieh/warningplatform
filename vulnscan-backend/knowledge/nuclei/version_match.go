package nuclei

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// semVersion represents a parsed semantic version (major.minor.patch).
type semVersion struct {
	Major, Minor, Patch int
	Raw                 string
}

var semverRe = regexp.MustCompile(`^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

func parseSemVersion(s string) (semVersion, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return semVersion{}, false
	}
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return semVersion{}, false
	}
	sv := semVersion{Raw: s}
	sv.Major, _ = strconv.Atoi(m[1])
	if m[2] != "" {
		sv.Minor, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		sv.Patch, _ = strconv.Atoi(m[3])
	}
	return sv, true
}

func (a semVersion) Compare(b semVersion) int {
	if a.Major != b.Major {
		return a.Major - b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor - b.Minor
	}
	return a.Patch - b.Patch
}

func (a semVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", a.Major, a.Minor, a.Patch)
}

// MatchVersionRange checks if a version string is within an affected version range.
// Supported formats:
//   - "< 2.4.50"
//   - ">= 2.4.0, < 2.4.50"
//   - ">= 8.0 AND < 8.0.28"
//   - "<= 1.0.0 || >= 2.0.0, < 2.1.0"
//   - "all" (matches any version)
//   - exact version "2.4.49"
func MatchVersionRange(version, rangeExpr string) bool {
	version = strings.TrimSpace(version)
	rangeExpr = strings.TrimSpace(rangeExpr)
	if version == "" || rangeExpr == "" {
		return false
	}
	if strings.EqualFold(rangeExpr, "all") || rangeExpr == "*" {
		return true
	}

	ver, ok := parseSemVersion(version)
	if !ok {
		return false
	}

	orParts := strings.Split(rangeExpr, "||")
	for _, orPart := range orParts {
		orPart = strings.TrimSpace(orPart)
		if orPart == "" {
			continue
		}
		if matchConjunction(ver, orPart) {
			return true
		}
	}
	return false
}

var rangeTokenRe = regexp.MustCompile(`(?i)\s*(?:,|AND)\s*`)

func matchConjunction(ver semVersion, expr string) bool {
	parts := rangeTokenRe.Split(expr, -1)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !matchSingleConstraint(ver, part) {
			return false
		}
	}
	return true
}

var constraintRe = regexp.MustCompile(`^(>=|<=|!=|>|<|=)?(.+)$`)

func matchSingleConstraint(ver semVersion, constraint string) bool {
	m := constraintRe.FindStringSubmatch(strings.TrimSpace(constraint))
	if m == nil {
		return false
	}
	op := m[1]
	if op == "" {
		op = "="
	}
	target, ok := parseSemVersion(m[2])
	if !ok {
		return false
	}

	cmp := ver.Compare(target)
	switch op {
	case "=":
		return cmp == 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case "!=":
		return cmp != 0
	default:
		return false
	}
}

// DetectedProduct represents a product identified by the fingerprint/tech-detect modules.
type DetectedProduct struct {
	Name    string
	Version string
	Vendor  string
}

// ParseDetectedProducts converts the raw detected_products strings into structured DetectedProduct.
// The format can be "product", "product:version", or "vendor/product:version".
func ParseDetectedProducts(raw []string) []DetectedProduct {
	out := make([]DetectedProduct, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		dp := DetectedProduct{}
		if idx := strings.Index(r, "/"); idx > 0 {
			dp.Vendor = r[:idx]
			r = r[idx+1:]
		}
		if idx := strings.LastIndex(r, ":"); idx > 0 {
			dp.Name = r[:idx]
			dp.Version = r[idx+1:]
		} else {
			dp.Name = r
		}
		out = append(out, dp)
	}
	return out
}

// MatchDecision records why a PoC was selected or skipped during matching.
type MatchDecision struct {
	PocID        string `json:"poc_id"`
	PocName      string `json:"poc_name"`
	Matched      bool   `json:"matched"`
	MatchMethod  string `json:"match_method"`
	MatchProduct string `json:"match_product,omitempty"`
	MatchVersion string `json:"match_version,omitempty"`
	Reason       string `json:"reason"`
}
