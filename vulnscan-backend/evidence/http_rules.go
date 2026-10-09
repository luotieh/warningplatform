package evidence

import (
	"math"
	"net"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

func parsedURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, false
	}
	return u, true
}
func skeleton(text string) string {
	replacer := strings.NewReplacer("rn", "m", "0", "o", "1", "l", "а", "a", "е", "e", "о", "o", "р", "p", "с", "c", "у", "y", "х", "x", "і", "i", "ο", "o", "ρ", "p")
	return replacer.Replace(strings.ToLower(text))
}
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	row := make([]int, len(y)+1)
	for i := range row {
		row[i] = i
	}
	for i, c := range x {
		next := make([]int, len(y)+1)
		next[0] = i + 1
		for j, d := range y {
			cost := 0
			if c != d {
				cost = 1
			}
			next[j+1] = min(next[j]+1, row[j+1]+1, row[j]+cost)
		}
		row = next
	}
	return row[len(y)]
}
func authorized(domain string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(domain, a) {
			return true
		}
	}
	return false
}
func credentialFields(fields map[string]string) bool {
	for name := range fields {
		switch strings.ToLower(name) {
		case "password", "passwd", "pwd", "otp", "one_time_password", "credit_card", "card_number", "cvv":
			return true
		}
	}
	return false
}

func (e *Engine) httpFact(f Finding, g *observations) Finding {
	if f.FactID == "F_LONG_LOW_SESSION" {
		return e.longSession(f, g)
	}
	if g.input == nil || g.input.HTTP == nil {
		return absent(f, MissingInput)
	}
	h := g.input.HTTP
	dependency(&f, "http", h.Provenance)
	if !provenance(h.Provenance) || !h.Complete || len(h.Records) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	f.SourceIDs = append(f.SourceIDs, h.SourceIDs...)
	refs := []string{}
	urls := []*url.URL{}
	for _, r := range h.Records {
		u, ok := parsedURL(r.URL)
		if !ok || r.SourceID == "" || r.Time.IsZero() {
			return absent(f, MissingInput)
		}
		urls = append(urls, u)
		refs = append(refs, r.SourceID)
	}
	switch f.FactID {
	case "F_HTTP_ENDPOINT_REPEAT":
		if len(h.Records) < 6 {
			return absent(f, InsufficientSamples)
		}
		groups := map[string][]HTTPRecord{}
		for i, r := range h.Records {
			path := urls[i].EscapedPath()
			if path == "" {
				path = "/"
			}
			key := strings.ToLower(urls[i].Host) + path
			groups[key] = append(groups[key], r)
		}
		best := 0.0
		for _, records := range groups {
			if len(records) < 6 {
				continue
			}
			sort.Slice(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
			intervals := []float64{}
			for i := 1; i < len(records); i++ {
				intervals = append(intervals, records[i].Time.Sub(records[i-1].Time).Seconds())
			}
			avg, cv := moments(intervals)
			if avg > 0 && cv <= 0.3 && float64(len(records)) > best {
				best = float64(len(records))
			}
		}
		return finish(f, best >= 6, map[string]float64{"max_repeated_endpoint_count": best}, refs...)
	case "F_HTTP_FIELD_ENCODING":
		b, ok := baseline(&f, g, "encoded_field_ratio_p95", "encoded_field_length_p95")
		if !ok {
			return absent(f, MissingBaseline)
		}
		total, count, longest := 0, 0, 0
		for _, r := range h.Records {
			if r.Truncated || r.FieldValuesRedacted && r.EncodingSummary == nil {
				return absent(f, UnverifiedCoverage)
			}
			if r.EncodingSummary != nil {
				s := r.EncodingSummary
				if s.Total < 0 || s.Encoded < 0 || s.Encoded > s.Total || s.Longest < 0 || s.Encoded == 0 && s.Longest != 0 || s.Encoded > 0 && s.Longest == 0 {
					return absent(f, MissingInput)
				}
				total += s.Total
				count += s.Encoded
				longest = max(longest, s.Longest)
				continue
			}
			for name, value := range r.Fields {
				total++
				lower := strings.ToLower(name)
				if strings.Contains(lower, "oauth") || lower == "authorization" || lower == "access_token" || strings.Count(value, ".") == 2 {
					continue
				}
				if decodedEncoding(value) != "" {
					count++
					if len(value) > longest {
						longest = len(value)
					}
				}
			}
		}
		if total == 0 {
			return absent(f, MissingInput)
		}
		ratio := float64(count) / float64(total)
		return finish(f, ratio > b[0] || float64(longest) > b[1], map[string]float64{"encoded_field_ratio": ratio, "max_encoded_length": float64(longest)}, refs...)
	case "F_HTTP_UA_RARITY":
		ua := h.Records[0].UserAgent
		if ua == "" {
			return absent(f, MissingInput)
		}
		for _, r := range h.Records {
			if r.UserAgent != ua {
				return finish(f, false, map[string]float64{"consistent_ua": 0}, refs...)
			}
		}
		b, ok := baseline(&f, g, "ua_frequency", "ua_frequency_p01")
		if !ok {
			return absent(f, MissingBaseline)
		}
		return finish(f, b[0] < b[1], map[string]float64{"ua_frequency": b[0], "ua_frequency_p01": b[1]}, refs...)
	case "F_HTTP_SIZE_STABILITY":
		if len(h.Records) < 12 {
			return absent(f, InsufficientSamples)
		}
		sizes := []float64{}
		distinct := map[uint64]bool{}
		for _, r := range h.Records {
			if r.BodyLength == nil || r.Truncated {
				return absent(f, MissingInput)
			}
			sizes = append(sizes, float64(*r.BodyLength))
			distinct[*r.BodyLength] = true
		}
		b, ok := baseline(&f, g, "size_cv_p05", "unique_size_ratio_p05")
		if !ok {
			return absent(f, MissingBaseline)
		}
		avg, cv := moments(sizes)
		ratio := float64(len(distinct)) / float64(len(sizes))
		return finish(f, avg > 0 && cv < b[0] && ratio < b[1], map[string]float64{"size_cv": cv, "unique_size_ratio": ratio}, refs...)
	case "F_URL_ODD_AUTHORITY":
		count := 0
		for _, u := range urls {
			host := u.Hostname()
			numeric := true
			for _, r := range host {
				if !unicode.IsDigit(r) {
					numeric = false
				}
			}
			if u.User != nil || net.ParseIP(host) != nil || numeric || strings.HasPrefix(strings.ToLower(host), "0x") {
				count++
			}
		}
		f.Limitations = append(f.Limitations, "异常authority只提供弱结构线索，不满足钓鱼欺骗门槛")
		return finish(f, count > 0, map[string]float64{"odd_authority_count": float64(count)}, refs...)
	case "F_URL_HOMOGLYPH":
		if !h.BrandsVerified || len(h.Brands) == 0 {
			return absent(f, MissingInput)
		}
		count := 0
		confusions := []string{}
		for _, u := range urls {
			unicodeHost, err := idna.Lookup.ToUnicode(u.Hostname())
			if err != nil {
				return absent(f, MissingInput)
			}
			root, valid := registrable(u.Hostname())
			if !valid {
				return absent(f, MissingInput)
			}
			unicodeHost, err = idna.Lookup.ToUnicode(root)
			if err != nil {
				return absent(f, MissingInput)
			}
			for _, brand := range h.Brands {
				for _, target := range brand.AuthorizedDomains {
					if !strings.EqualFold(unicodeHost, target) && skeleton(unicodeHost) == skeleton(target) {
						count++
						for _, r := range unicodeHost {
							if r > 127 || r == '0' || r == '1' {
								confusions = append(confusions, string(r))
							}
						}
					}
				}
			}
		}
		f.Measurements.Labels = unique(confusions)
		f.Limitations = append(f.Limitations, "使用有限的显式混淆映射；不宣称覆盖所有Unicode视觉混淆")
		return finish(f, count > 0, map[string]float64{"confusable_hosts": float64(count)}, refs...)
	case "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR":
		if !h.BrandsVerified || len(h.Brands) == 0 {
			return absent(f, MissingInput)
		}
		count := 0
		maxDistance := 1.0
		if f.FactID == "F_BRAND_IMPOSTOR" {
			v, ok := e.policy(&f, "max_edit_distance")
			if !ok || v < 1 || v != math.Trunc(v) {
				return absent(f, MissingPolicy)
			}
			maxDistance = v
		}
		for recordIndex, u := range urls {
			root, ok := registrable(u.Hostname())
			if !ok {
				return absent(f, MissingInput)
			}
			for _, brand := range h.Brands {
				if len(brand.AuthorizedDomains) == 0 {
					return absent(f, MissingInput)
				}
				if authorized(root, brand.AuthorizedDomains) {
					continue
				}
				if f.FactID == "F_URL_BRAND_SUBDOMAIN_TRICK" {
					sub := strings.TrimSuffix(strings.ToLower(u.Hostname()), "."+root)
					if sub != root && brand.Name != "" && strings.Contains(sub, strings.ToLower(brand.Name)) {
						count++
					}
				} else {
					record := h.Records[recordIndex]
					if record.DeclaredBrand != "" {
						if !record.BrandClaimVerified {
							return absent(f, MissingInput)
						}
						if strings.EqualFold(record.DeclaredBrand, brand.Name) {
							count++
							continue
						}
					}
					for _, allowed := range brand.AuthorizedDomains {
						if float64(editDistance(root, allowed)) <= maxDistance {
							count++
							break
						}
					}
				}
			}
		}
		return finish(f, count > 0, map[string]float64{"brand_structure_matches": float64(count)}, refs...)
	case "F_CRED_POST_STRUCTURE":
		count := 0
		for _, r := range h.Records {
			if r.Truncated {
				return absent(f, UnverifiedCoverage)
			}
			if strings.EqualFold(r.Method, "POST") && credentialFields(r.Fields) {
				count++
			}
		}
		return finish(f, count > 0, map[string]float64{"credential_post_count": float64(count)}, refs...)
	case "F_FORM_CROSSSITE":
		count := 0
		seen := 0
		for i, r := range h.Records {
			if r.Truncated {
				return absent(f, UnverifiedCoverage)
			}
			if r.FormAction == "" {
				continue
			}
			seen++
			action, err := urls[i].Parse(r.FormAction)
			if err != nil {
				return absent(f, MissingInput)
			}
			a, ok := registrable(urls[i].Hostname())
			b, valid := registrable(action.Hostname())
			if !ok || !valid {
				return absent(f, MissingInput)
			}
			if a != b {
				count++
			}
		}
		if seen == 0 {
			return absent(f, MissingInput)
		}
		return finish(f, count > 0, map[string]float64{"crosssite_forms": float64(count)}, refs...)
	case "F_REDIRECT_CHAIN", "F_MULTI_REDIRECT_CHAIN":
		return e.redirects(f, h, refs)
	}
	return absent(f, MissingInput)
}

func (e *Engine) redirects(f Finding, h *HTTPData, refs []string) Finding {
	byID := map[string]HTTPRecord{}
	for _, r := range h.Records {
		if r.TransactionID == "" || byID[r.TransactionID].TransactionID != "" {
			return absent(f, UnresolvedBinding)
		}
		byID[r.TransactionID] = r
	}
	best := 0
	matched := false
	for _, start := range h.Records {
		current := start
		seen := map[string]bool{}
		length := 0
		cross := false
		for current.RedirectToTransactionID != "" {
			if seen[current.TransactionID] {
				return absent(f, UnresolvedBinding)
			}
			seen[current.TransactionID] = true
			next, ok := byID[current.RedirectToTransactionID]
			if !ok || !current.RedirectVerified || !current.ResponseVerified || current.ResponseLocation == "" || current.ResponseStatus < 300 || current.ResponseStatus >= 400 || current.SessionID == "" || current.SessionID != next.SessionID || next.Time.Before(current.Time) {
				return absent(f, UnresolvedBinding)
			}
			u, _ := parsedURL(current.URL)
			v, _ := parsedURL(next.URL)
			target, err := u.Parse(current.ResponseLocation)
			if err != nil || target.String() != v.String() {
				return absent(f, UnresolvedBinding)
			}
			a, ok := registrable(u.Hostname())
			b, valid := registrable(v.Hostname())
			if !ok || !valid {
				return absent(f, MissingInput)
			}
			if a != b {
				cross = true
			}
			length++
			current = next
		}
		if length > best {
			best = length
		}
		if f.FactID == "F_REDIRECT_CHAIN" && length > 0 && cross && strings.EqualFold(current.Method, "POST") && credentialFields(current.Fields) && !current.Truncated {
			matched = true
		}
		if f.FactID == "F_MULTI_REDIRECT_CHAIN" && length >= 2 {
			matched = true
		}
	}
	return finish(f, matched, map[string]float64{"max_redirect_edges": float64(best)}, refs...)
}

// Extract features before redaction without retaining reversible secrets.
func SummarizeHTTPFieldEncoding(fields map[string]string) HTTPFieldEncodingSummary {
	s := HTTPFieldEncodingSummary{}
	for name, value := range fields {
		s.Total++
		lower := strings.ToLower(name)
		if strings.Contains(lower, "oauth") || lower == "authorization" || lower == "access_token" || strings.Count(value, ".") == 2 {
			continue
		}
		if decodedEncoding(value) != "" {
			s.Encoded++
			s.Longest = max(s.Longest, len(value))
		}
	}
	return s
}

func (e *Engine) longSession(f Finding, g *observations) Finding {
	if g.input == nil || g.input.Network == nil || !provenance(g.input.Network.Provenance) {
		return absent(f, MissingInput)
	}
	n := g.input.Network
	dependency(&f, "network", n.Provenance)
	if !n.Complete || len(n.Sessions) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	refs := append([]string(nil), n.SourceIDs...)
	for _, s := range n.Sessions {
		if !s.VolumeVerified || s.ID == "" || s.Start.IsZero() || s.End.IsZero() || !s.Start.Before(s.End) || s.SourceID == "" {
			return absent(f, MissingInput)
		}
		refs = append(refs, s.SourceID)
		if s.End.Sub(s.Start).Seconds() <= 1800 || s.UpBytes == 0 || s.DownBytes == 0 || s.UpBytes >= 10240 || s.DownBytes >= 10240 || s.UpBytes+s.DownBytes >= 10240 {
			continue
		}
		hits := []Hit{}
		for _, id := range s.HitIDs {
			for _, hit := range g.hits {
				if hit.ID == id && !hit.OccurredAt.Before(s.Start) && !hit.OccurredAt.After(s.End) {
					hits = append(hits, hit)
				}
			}
		}
		sub := &observations{scope: g.scope, hits: hits, complete: g.complete}
		if len(hits) == 0 {
			return absent(f, UnresolvedBinding)
		}
		periodic := e.periodic(sub)
		if periodic.Status == Missing {
			return absent(f, periodic.ReasonCode)
		}
		if periodic.Status == Observed {
			return finish(f, true, map[string]float64{"duration_sec": s.End.Sub(s.Start).Seconds(), "bidirectional_bytes": float64(s.UpBytes + s.DownBytes)}, refs...)
		}
	}
	return finish(f, false, map[string]float64{"matching_sessions": 0}, refs...)
}
