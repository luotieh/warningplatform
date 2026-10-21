package evidence

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
	"unicode"
)

func hasHTTPRequestVerification(h *HTTPData) bool {
	for _, r := range h.Records {
		if r.RequestVerification != nil {
			return true
		}
	}
	return false
}

// HTTPRequestFieldNames returns a canonical inventory without retaining values.
func HTTPRequestFieldNames(fields map[string]string) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func verifiedHTTPRequestFields(r HTTPRecord) bool {
	v := r.RequestVerification
	if v == nil || !v.FieldsVerified {
		return false
	}
	names := HTTPRequestFieldNames(r.Fields)
	if len(names) != len(v.FieldNames) {
		return false
	}
	for i, name := range names {
		if name != v.FieldNames[i] {
			return false
		}
	}
	return true
}

// verifiedHTTPRequestObservation checks only the explicitly bound complete request
// collection. Neither an eligible negative nor its window describes unobserved
// requests. Other HTTP rules retain their complete-family gate.
func verifiedHTTPRequestObservation(f Finding, g *observations) Finding {
	h := g.input.HTTP
	credential := f.FactID == "F_CRED_POST_STRUCTURE"
	f.SourceIDs = nil
	f.ObservationKind = "complete_http_request"
	f.Measurements.SampleCount = 0
	f.Quality = "verified_request_subset"
	if credential {
		f.Limitations = append(f.Limitations, "仅判定列出的字段名完整核验请求是否具备凭据POST结构；阴性不代表整个事件或窗口内不存在凭据POST", "只核验方法与字段名，不证明凭据真实、已提交成功或恶意收集")
	} else {
		f.Limitations = append(f.Limitations, "仅判定列出的已验证完整请求URL结构；未发现异常不代表事件或窗口内其他请求不存在异常", "异常authority只提供弱结构线索，不满足钓鱼欺骗门槛")
	}
	if !provenance(h.Provenance) || g.input.Window == nil || !g.input.Window.Start.Before(g.input.Window.End) {
		return absent(f, UnverifiedCoverage)
	}
	sources := map[string]bool{}
	for _, id := range h.SourceIDs {
		sources[id] = true
	}
	hits := map[string]Hit{}
	for _, hit := range g.hits {
		hits[hit.ID] = hit
	}
	groups := map[string][]HTTPRecord{}
	conflicts := map[string]bool{}
	skipped := 0
	for _, r := range h.Records {
		v := r.RequestVerification
		if v == nil {
			skipped++
			continue
		}
		hit, bound := hits[r.SourceID]
		_, urlOK := parsedURL(r.URL)
		valid := !r.Truncated && v.Version == HTTPRequestVerificationVersion && v.Scope == g.scope && r.SourceID != "" && sources[r.SourceID] && bound && hit.Scope == g.scope && hit.OccurredAt.Equal(v.SourceOccurredAt) &&
			r.RequestID != "" && r.RequestID == v.RequestID && r.SourceID == v.SourceID && !r.Time.IsZero() && r.Time.Equal(v.RequestTime) && r.URL == v.URL && urlOK && r.Method != "" && r.Method == v.Method && r.SessionID != "" && r.SessionID == v.SessionID &&
			!hit.OccurredAt.Before(g.input.Window.Start) && hit.OccurredAt.Before(g.input.Window.End) && !r.Time.Before(g.input.Window.Start) && r.Time.Before(g.input.Window.End)
		if credential {
			valid = valid && verifiedHTTPRequestFields(r)
		}
		if !valid {
			skipped++
			// A stale/conflicting marker cannot authorize another projection of
			// that same request merely because one copy is still consistent.
			if r.RequestID != "" {
				conflicts[r.RequestID] = true
			}
			if v.RequestID != "" {
				conflicts[v.RequestID] = true
			}
			continue
		}
		if rows := groups[r.RequestID]; len(rows) > 0 {
			first := rows[0]
			if first.URL != r.URL || first.Method != r.Method || first.SessionID != r.SessionID || !first.Time.Equal(r.Time) {
				conflicts[r.RequestID] = true
			}
			if credential && !equalHTTPFieldNames(first.RequestVerification.FieldNames, v.FieldNames) {
				conflicts[r.RequestID] = true
			}
		}
		groups[r.RequestID] = append(groups[r.RequestID], r)
	}
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	refs := []string{}
	count, excludedGroups, duplicateRows := 0, 0, 0
	var start, end time.Time
	for _, id := range ids {
		rows := groups[id]
		if conflicts[id] {
			excludedGroups++
			skipped += len(rows)
			continue
		}
		r := rows[0]
		if credential {
			if strings.EqualFold(r.Method, "POST") && credentialFields(r.Fields) {
				count++
			}
		} else {
			u, _ := parsedURL(r.URL)
			host := u.Hostname()
			numeric := true
			for _, c := range host {
				if !unicode.IsDigit(c) {
					numeric = false
				}
			}
			if u.User != nil || net.ParseIP(host) != nil || numeric || strings.HasPrefix(strings.ToLower(host), "0x") {
				count++
			}
		}
		f.Measurements.SampleCount++
		duplicateRows += len(rows) - 1
		for _, row := range rows {
			refs = append(refs, row.SourceID)
		}
		if start.IsZero() || r.Time.Before(start) {
			start = r.Time
		}
		if end.IsZero() || r.Time.After(end) {
			end = r.Time
		}
	}
	f.Limitations = append(f.Limitations, fmt.Sprintf("已验证去重请求=%d；跳过投影=%d；冲突请求组=%d；重复投影=%d；排除投影保留在原Bundle中", f.Measurements.SampleCount, skipped, excludedGroups, duplicateRows))
	metric := "odd_authority_count"
	if credential {
		metric = "credential_post_count"
	}
	f.Measurements.Values = map[string]float64{metric: float64(count), "excluded_request_projections": float64(skipped), "conflicting_request_groups": float64(excludedGroups), "duplicate_request_projections": float64(duplicateRows)}
	if f.Measurements.SampleCount == 0 {
		return absent(f, UnresolvedBinding)
	}
	f.Window = &Window{Start: start, End: end, Convention: "verified_request_subset_first_last_inclusive"}
	refs = unique(refs)
	f.Dependencies = append(f.Dependencies, Dependency{Kind: "verified_http_request_subset", Version: h.Version + ":" + HTTPRequestVerificationVersion, SourceIDs: append([]string(nil), refs...)})
	return finish(f, count > 0, f.Measurements.Values, refs...)
}

func equalHTTPFieldNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
