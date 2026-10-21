package service

import (
	"strings"
	"unicode"
)

// providerObservedDomainMatchesIOC relates an already verified DNS question
// name to its declared domain IOC. Callers must verify the original frame and
// question source independently; this predicate proves neither capture/window
// completeness nor a new contact, DNS answer association, or HTTP/TLS binding.
//
// Normalization and matching mirror ta_node/internal/intel/matcher.go:
// canonicalDomain lowercases, trims surrounding space and one terminal dot;
// matchDomainLocked accepts equality or a whole-label subdomain suffix.
// Reject non-name inputs rather than extracting a host from a URL or accepting
// a URL-looking string merely because it ends with the declared domain.
func providerObservedDomainMatchesIOC(observedName, iocDomain string) bool {
	canonical := func(value string) string {
		return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	}
	observed, ioc := canonical(observedName), canonical(iocDomain)
	nameOnly := func(value string) bool {
		if value == "" || strings.ContainsAny(value, "/\\:@?#%[]") {
			return false
		}
		if strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return false
		}
		for _, label := range strings.Split(value, ".") {
			if label == "" {
				return false
			}
		}
		return true
	}
	if !nameOnly(observed) || !nameOnly(ioc) {
		return false
	}
	return observed == ioc || strings.HasSuffix(observed, "."+ioc)
}
