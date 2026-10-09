package evidence

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math"
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

func canonicalDomain(raw string) (string, bool) {
	s, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), "."))
	if err != nil || s == "" || strings.ContainsAny(s, " /@:") {
		return "", false
	}
	return s, true
}
func registrable(raw string) (string, bool) {
	s, ok := canonicalDomain(raw)
	if !ok || net.ParseIP(s) != nil {
		return "", false
	}
	r, err := publicsuffix.EffectiveTLDPlusOne(s)
	return r, err == nil
}
func decodedEncoding(raw string) string {
	if len(raw) < 8 {
		return ""
	}
	if len(raw)%2 == 0 {
		if b, err := hex.DecodeString(raw); err == nil && len(b) >= 4 {
			return "hex"
		}
	}
	if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(raw)); err == nil && len(b) >= 4 && strings.EqualFold(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), raw) {
		return "base32"
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil && len(b) >= 4 && enc.EncodeToString(b) == raw {
			return "base64"
		}
	}
	return ""
}
func (e *Engine) dnsFact(f Finding, g *observations) Finding {
	if g.input == nil || g.input.DNS == nil {
		return absent(f, MissingInput)
	}
	d := g.input.DNS
	dependency(&f, "dns", d.Provenance)
	if !provenance(d.Provenance) || !d.Complete || len(d.Records) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	f.SourceIDs = append(f.SourceIDs, d.SourceIDs...)
	refs := []string{}
	domains := []string{}
	roots := []string{}
	for _, r := range d.Records {
		domain, ok := canonicalDomain(r.Domain)
		root, valid := registrable(r.Domain)
		if !ok || !valid || r.SourceID == "" || r.Time.IsZero() {
			return absent(f, MissingInput)
		}
		domains = append(domains, domain)
		roots = append(roots, root)
		refs = append(refs, r.SourceID)
	}
	switch f.FactID {
	case "F_DNS_ENCODED_LABEL":
		count := 0
		encodings := []string{}
		for _, domain := range domains {
			for _, label := range strings.Split(domain, ".") {
				enc := decodedEncoding(label)
				if enc == "hex" || enc == "base32" {
					count++
					encodings = append(encodings, enc)
				}
			}
		}
		f.Measurements.Labels = unique(encodings)
		return finish(f, count > 0, map[string]float64{"validated_encoded_labels": float64(count)}, refs...)
	case "F_DNS_HIGH_ENTROPY":
		if len(unique(roots)) != 1 || g.input.Window == nil {
			return absent(f, UnresolvedBinding)
		}
		seconds := g.input.Window.End.Sub(g.input.Window.Start).Seconds()
		if seconds <= 0 {
			return absent(f, MissingInput)
		}
		b, ok := baseline(&f, g, "unique_subdomain_ratio_p95", "label_length_p95", "query_rate_p95")
		if !ok {
			return absent(f, MissingBaseline)
		}
		labels := []string{}
		lengths := []float64{}
		for i, domain := range domains {
			sub := strings.TrimSuffix(domain, "."+roots[i])
			if sub == roots[i] {
				sub = ""
			}
			labels = append(labels, sub)
			for _, label := range strings.Split(sub, ".") {
				lengths = append(lengths, float64(len(label)))
			}
		}
		ratio := float64(len(unique(labels))) / float64(len(domains))
		length := quantile(lengths, 0.9)
		rate := float64(len(domains)) / seconds
		return finish(f, ratio > b[0] && length > b[1] && rate > b[2], map[string]float64{"unique_subdomain_ratio": ratio, "label_length_p90": length, "queries_per_second": rate}, refs...)
	case "F_DGA_LEXICAL":
		b, ok := baseline(&f, g, "bigram_log_probability_p05", "vowel_ratio_p05", "vowel_ratio_p95", "length_p05", "length_p95")
		if !ok || len(d.BigramLogProbabilities) == 0 {
			return absent(f, MissingBaseline)
		}
		match := 0
		minimum := math.Inf(1)
		for _, root := range roots {
			label := strings.Split(root, ".")[0]
			if len(label) < 2 || !utf8.ValidString(label) {
				return absent(f, MissingInput)
			}
			sum, vowels := 0.0, 0
			for i := 0; i < len(label)-1; i++ {
				p, exists := d.BigramLogProbabilities[label[i:i+2]]
				if !exists || !finite(p) || p > 0 {
					return absent(f, MissingBaseline)
				}
				sum += p
			}
			score := sum / float64(len(label)-1)
			for _, r := range label {
				if strings.ContainsRune("aeiou", r) {
					vowels++
				}
			}
			ratio := float64(vowels) / float64(len(label))
			if score < minimum {
				minimum = score
			}
			shape := ratio < b[1] || ratio > b[2] || float64(len(label)) < b[3] || float64(len(label)) > b[4]
			if score < b[0] && shape {
				match++
			}
		}
		return finish(f, match > 0, map[string]float64{"matching_domains": float64(match), "minimum_bigram_log_probability": minimum}, refs...)
	case "F_NXDOMAIN_CLUSTER":
		b, ok := baseline(&f, g, "nxdomain_rate_p99")
		if !ok || b[0] < 0 || b[0] > 1 {
			return absent(f, MissingBaseline)
		}
		failed := 0
		failedRoots := []string{}
		for i, r := range d.Records {
			if !r.RCodeKnown {
				return absent(f, MissingInput)
			}
			if r.RCode == 3 {
				failed++
				failedRoots = append(failedRoots, roots[i])
			}
		}
		rate := float64(failed) / float64(len(d.Records))
		return finish(f, len(unique(failedRoots)) >= 2 && rate > b[0], map[string]float64{"failure_rate": rate, "failed_registrable_domains": float64(len(unique(failedRoots)))}, refs...)
	case "F_FAILED_TO_ACTIVE":
		if g.input.Network == nil || !provenance(g.input.Network.Provenance) || !g.input.Network.Complete {
			return absent(f, MissingInput)
		}
		minFailures, ok := e.policy(&f, "min_failures")
		if !ok || minFailures < 2 || minFailures != math.Trunc(minFailures) {
			return absent(f, MissingPolicy)
		}
		for _, resolved := range d.Records {
			if !resolved.RCodeKnown {
				return absent(f, MissingInput)
			}
			if resolved.RCode != 0 || len(resolved.Answers) == 0 {
				continue
			}
			fails := 0
			for _, earlier := range d.Records {
				if earlier.Time.Before(resolved.Time) && earlier.RCodeKnown && earlier.RCode == 3 {
					fails++
				}
			}
			if float64(fails) < minFailures {
				continue
			}
			for _, connection := range g.input.Network.Connections {
				delay := connection.Time.Sub(resolved.Time).Seconds()
				if delay >= 0 && delay <= 300 {
					for _, ip := range resolved.Answers {
						if ip == connection.Destination {
							return finish(f, true, map[string]float64{"prior_failures": float64(fails), "connection_delay_sec": delay}, append(refs, connection.SourceID)...)
						}
					}
				}
			}
		}
		return finish(f, false, map[string]float64{"matched_chains": 0}, refs...)
	}
	return absent(f, MissingInput)
}
