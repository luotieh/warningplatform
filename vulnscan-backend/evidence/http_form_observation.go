package evidence

import (
	"encoding/hex"
	"time"
)

func verifiedHTTPForms(r HTTPRecord, scope Scope) bool {
	v := r.FormVerification
	if v == nil || v.Version != HTTPFormVerificationVersion || v.Scope != scope || v.SourceID != r.SourceID || r.RequestVerification == nil || !v.SourceOccurredAt.Equal(r.RequestVerification.SourceOccurredAt) || v.RequestID != r.RequestID || v.SessionID != r.SessionID || v.TransactionID == "" || v.TransactionID != r.TransactionID || v.PageURL != r.URL || r.ResponseURL != r.URL || !r.ResponseVerified || v.ResponseStatus != r.ResponseStatus || v.ResponseStatus < 200 || v.ResponseStatus >= 300 {
		return false
	}
	digest, err := hex.DecodeString(v.ResponseSHA256)
	if err != nil || len(digest) != 32 {
		return false
	}
	for _, action := range v.Actions {
		if _, ok := parsedURL(action); !ok {
			return false
		}
	}
	return true
}

func equalHTTPForms(a, b *HTTPFormVerification) bool {
	if a == nil || b == nil || a.PageURL != b.PageURL || a.TransactionID != b.TransactionID || a.ResponseStatus != b.ResponseStatus || a.ResponseSHA256 != b.ResponseSHA256 || len(a.Actions) != len(b.Actions) {
		return false
	}
	for i := range a.Actions {
		if a.Actions[i] != b.Actions[i] {
			return false
		}
	}
	return true
}

func verifiedHTTPFormDestinations(f Finding, h *HTTPData, records []HTTPRecord, refs []string, start, end time.Time) Finding {
	forms, cross := 0, 0
	for _, r := range records {
		page, _ := parsedURL(r.URL)
		root, ok := registrable(page.Hostname())
		if !ok {
			return absent(f, MissingInput)
		}
		for _, action := range r.FormVerification.Actions {
			target, _ := parsedURL(action)
			other, valid := registrable(target.Hostname())
			if !valid {
				return absent(f, MissingInput)
			}
			forms++
			if root != other {
				cross++
			}
		}
	}
	f.Measurements.Values = map[string]float64{"verified_html_responses": float64(len(records)), "static_forms": float64(forms), "crosssite_forms": float64(cross)}
	f.SourceIDs = unique(refs)
	if len(records) == 0 || forms == 0 {
		return absent(f, MissingInput)
	}
	f.Window = &Window{Start: start, End: end, Convention: "verified_request_subset_first_last_inclusive"}
	f.Dependencies = append(f.Dependencies, Dependency{Kind: "verified_static_html_forms", Version: h.Version + ":" + HTTPFormVerificationVersion, SourceIDs: unique(refs)})
	return finish(f, cross > 0, f.Measurements.Values, refs...)
}
