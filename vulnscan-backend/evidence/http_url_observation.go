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

func equalHTTPEncodingSummary(a, b *HTTPFieldEncodingSummary) bool {
	return a != nil && b != nil && *a == *b
}

func verifiedHTTPRequestEncoding(r HTTPRecord) bool {
	v := r.RequestVerification
	if !verifiedHTTPRequestFields(r) || !v.EncodingSummaryVerified || !equalHTTPEncodingSummary(r.EncodingSummary, v.EncodingSummary) {
		return false
	}
	s := r.EncodingSummary
	return s.Total == len(v.FieldNames) && s.Encoded >= 0 && s.Encoded <= s.Total && s.Longest >= 0 &&
		(s.Encoded != 0 || s.Longest == 0) && (s.Encoded == 0 || s.Longest > 0)
}

// verifiedHTTPRequestObservation checks only the explicitly bound complete request
// collection. Neither an eligible negative nor its window describes unobserved
// requests. Other HTTP rules retain their complete-family gate.
func verifiedHTTPRequestObservation(f Finding, g *observations) Finding {
	h := g.input.HTTP
	credential := f.FactID == "F_CRED_POST_STRUCTURE"
	endpointRepeat := f.FactID == "F_HTTP_ENDPOINT_REPEAT"
	fieldEncoding := f.FactID == "F_HTTP_FIELD_ENCODING"
	forms := f.FactID == "F_FORM_CROSSSITE"
	uaRarity := f.FactID == "F_HTTP_UA_RARITY"
	sizeStability := f.FactID == "F_HTTP_SIZE_STABILITY"
	f.SourceIDs = nil
	f.ObservationKind = "complete_http_request"
	f.Measurements.SampleCount = 0
	f.Quality = "verified_request_subset"
	if uaRarity || sizeStability {
		f.ObservationKind = "complete_http_request_statistics"
		f.FeatureClaim = "Source-bound header or request-body-size statistics among verified complete HTTP requests, using supplied normal baselines when required"
		f.CannotProve = "Does not prove maliciousness or complete HTTP capture; missing normal baselines cannot establish rarity or anomalous size stability"
		f.Limitations = append(f.Limitations, "仅使用已核验完整请求子集；UA或请求体长度须独立绑定并排除同请求冲突；不提升窗口完整性、不借响应长度代替请求体长度")
	} else if forms {
		f.ObservationKind = "verified_static_html_forms"
		f.FeatureClaim = "Static form destinations from complete source-bound paired HTML responses differ in registrable domain from their document URL"
		f.CannotProve = "Does not prove form submission, credentials sent, JavaScript behavior, maliciousness, or a complete event window"
		f.Limitations = append(f.Limitations, "仅核验已保存完整响应中的静态HTML表单，按首个base解析相对action；不推断实际提交或脚本行为；无表单不判定阴性")
	} else if fieldEncoding {
		f.ObservationKind = "complete_http_request_field_encoding"
		f.FeatureClaim = "Pre-redaction field encoding measurements among deduplicated verified complete HTTP requests, compared with the supplied verified baseline"
		f.CannotProve = "Does not prove a complete HTTP window, malicious payloads, or encoding behavior outside the listed request subset; baseline absence cannot yield a verdict"
		f.Limitations = append(f.Limitations, "仅聚合列出的完整请求中独立核验且与字段名集合一致的脱敏前编码摘要；不从URL验证标记推定字段值或摘要可信", "仅使用原算法及已提供的可信基线；阴性不代表整个事件或窗口不存在编码异常")
	} else if endpointRepeat {
		f.ObservationKind = "complete_http_request_endpoint_repeat"
		f.FeatureClaim = "Endpoint request timing structure among deduplicated verified complete HTTP requests"
		f.CannotProve = "Does not prove a complete HTTP window, malicious beaconing, or absence of repeated requests outside the listed subset"
		f.Limitations = append(f.Limitations, "仅在列出的已验证完整请求子集中，按当前scope与规范URL端点分别计算；每个端点至少6次请求，不合并不同目标的时间序列", "阴性仅表示所列请求子集中未满足固定端点重复条件，不代表整个事件或窗口不存在该行为")
	} else if credential {
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
		if fieldEncoding {
			valid = valid && verifiedHTTPRequestEncoding(r)
		}
		if forms {
			valid = valid && verifiedHTTPForms(r, g.scope)
		}
		if uaRarity {
			valid = valid && v.UserAgentVerified && v.UserAgent == r.UserAgent
		}
		if sizeStability {
			valid = valid && v.BodyLengthVerified && r.BodyLength != nil && *r.BodyLength == v.BodyLength
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
			if (credential || fieldEncoding) && !equalHTTPFieldNames(first.RequestVerification.FieldNames, v.FieldNames) {
				conflicts[r.RequestID] = true
			}
			if fieldEncoding && !equalHTTPEncodingSummary(first.EncodingSummary, r.EncodingSummary) {
				conflicts[r.RequestID] = true
			}
			if forms && !equalHTTPForms(first.FormVerification, r.FormVerification) {
				conflicts[r.RequestID] = true
			}
			if uaRarity && first.UserAgent != r.UserAgent {
				conflicts[r.RequestID] = true
			}
			if sizeStability && *first.BodyLength != *r.BodyLength {
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
	requestSubset := []HTTPRecord{}
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
		} else if !endpointRepeat && !fieldEncoding && !forms && !uaRarity && !sizeStability {
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
		if endpointRepeat || fieldEncoding || forms || uaRarity || sizeStability {
			requestSubset = append(requestSubset, r)
		}
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
	if uaRarity || sizeStability {
		return verifiedHTTPRequestStatistics(f, g, requestSubset, refs, start, end)
	}
	if forms {
		return verifiedHTTPFormDestinations(f, h, requestSubset, refs, start, end)
	}
	if endpointRepeat {
		return verifiedHTTPEndpointRepeat(f, h, requestSubset, refs, start, end, skipped, excludedGroups, duplicateRows)
	}
	if fieldEncoding {
		return verifiedHTTPFieldEncoding(f, g, requestSubset, refs, start, end, skipped, excludedGroups, duplicateRows)
	}
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

func verifiedHTTPFieldEncoding(f Finding, g *observations, records []HTTPRecord, refs []string, start, end time.Time, skipped, conflicts, duplicates int) Finding {
	total, encoded, longest := 0, 0, 0
	for _, r := range records {
		s := r.EncodingSummary // per-request authority and consistency checked above
		total += s.Total
		encoded += s.Encoded
		longest = max(longest, s.Longest)
	}
	f.Measurements.Values = map[string]float64{
		"field_count": float64(total), "encoded_field_count": float64(encoded), "max_encoded_length": float64(longest),
		"excluded_request_projections": float64(skipped), "conflicting_request_groups": float64(conflicts), "duplicate_request_projections": float64(duplicates),
	}
	if len(records) == 0 {
		return absent(f, UnresolvedBinding)
	}
	refs = unique(refs)
	f.SourceIDs = append([]string(nil), refs...)
	f.Window = &Window{Start: start, End: end, Convention: "verified_request_subset_first_last_inclusive"}
	f.Dependencies = append(f.Dependencies, Dependency{Kind: "verified_http_request_encoding_subset", Version: g.input.HTTP.Version + ":" + HTTPRequestVerificationVersion, SourceIDs: append([]string(nil), refs...)})
	if total == 0 {
		return absent(f, MissingInput)
	}
	ratio := float64(encoded) / float64(total)
	f.Measurements.Values["encoded_field_ratio"] = ratio
	b, ok := baseline(&f, g, "encoded_field_ratio_p95", "encoded_field_length_p95")
	if !ok {
		return absent(f, MissingBaseline)
	}
	return finish(f, ratio > b[0] || float64(longest) > b[1], f.Measurements.Values, refs...)
}

// Records have passed the same source, scope, time, request-identity and
// conflict-group checks used by URL structure. Field-name authority is not
// required for timing. Preserve the complete-family rule's endpoint key and
// >=6 / mean>0 / CV<=0.3 predicates, with a separate timeline for every target.
func verifiedHTTPEndpointRepeat(f Finding, h *HTTPData, records []HTTPRecord, refs []string, start, end time.Time, skipped, conflicts, duplicates int) Finding {
	f.Measurements.Values = map[string]float64{
		"max_repeated_endpoint_count":   0,
		"excluded_request_projections":  float64(skipped),
		"conflicting_request_groups":    float64(conflicts),
		"duplicate_request_projections": float64(duplicates),
		"qualified_endpoint_groups":     0,
	}
	if len(records) == 0 {
		return absent(f, UnresolvedBinding)
	}
	refs = unique(refs)
	f.SourceIDs = append([]string(nil), refs...)
	f.Window = &Window{Start: start, End: end, Convention: "verified_request_subset_first_last_inclusive"}
	f.Dependencies = append(f.Dependencies, Dependency{Kind: "verified_http_request_subset", Version: h.Version + ":" + HTTPRequestVerificationVersion, SourceIDs: append([]string(nil), refs...)})
	groups := map[string][]HTTPRecord{}
	for _, r := range records {
		u, _ := parsedURL(r.URL) // URL was validated before admitting the record.
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		key := strings.ToLower(u.Host) + path
		groups[key] = append(groups[key], r)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	best := 0.0
	qualified := 0
	for _, key := range keys {
		rows := groups[key]
		if len(rows) < 6 {
			continue
		}
		qualified++
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Time.Equal(rows[j].Time) {
				return rows[i].RequestID < rows[j].RequestID
			}
			return rows[i].Time.Before(rows[j].Time)
		})
		intervals := make([]float64, 0, len(rows)-1)
		for i := 1; i < len(rows); i++ {
			intervals = append(intervals, rows[i].Time.Sub(rows[i-1].Time).Seconds())
		}
		avg, cv := moments(intervals)
		f.Measurements.HTTPGroups = append(f.Measurements.HTTPGroups, HTTPRepeatGroup{Endpoint: key, Requests: len(rows), IntervalMeanSeconds: avg, IntervalCV: cv})
		if avg > 0 && cv <= 0.3 && float64(len(rows)) > best {
			best = float64(len(rows))
		}
	}
	f.Measurements.Values["qualified_endpoint_groups"] = float64(qualified)
	f.Measurements.Values["max_repeated_endpoint_count"] = best
	if qualified == 0 {
		return absent(f, InsufficientSamples)
	}
	return finish(f, best >= 6, f.Measurements.Values, refs...)
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
