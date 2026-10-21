package evidence

import (
	"encoding/json"
	"testing"
)

func credentialObservationRequest() Request {
	r := urlObservationRequest()
	r.Facts = []FactID{"F_CRED_POST_STRUCTURE"}
	for i := range r.Inputs[0].HTTP.Records {
		row := &r.Inputs[0].HTTP.Records[i]
		row.Fields = map[string]string{}
		row.RequestVerification.FieldsVerified = true
	}
	row := &r.Inputs[0].HTTP.Records[0]
	row.Method, row.RequestVerification.Method = "POST", "POST"
	row.Fields = map[string]string{"password": "[redacted]"}
	row.RequestVerification.FieldNames = HTTPRequestFieldNames(row.Fields)
	return r
}

func TestVerifiedHTTPCredentialObservation(t *testing.T) {
	r := credentialObservationRequest()
	raw, _ := json.Marshal(r)
	var decoded Request
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	f := evaluateURLObservation(t, decoded)
	if f.Status != Observed || f.Measurements.SampleCount != 2 || f.Measurements.Values["credential_post_count"] != 1 {
		t.Fatal("complete credential POST not detected", f)
	}
	for _, tc := range []struct {
		name   string
		change func(*HTTPRecord)
	}{
		{"changed_fields", func(r *HTTPRecord) { r.Fields = map[string]string{"ordinary": "[redacted]"} }},
		{"truncated", func(r *HTTPRecord) { r.Truncated = true }},
		{"unverified_fields", func(r *HTTPRecord) { r.RequestVerification.FieldsVerified = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := credentialObservationRequest()
			tc.change(&r.Inputs[0].HTTP.Records[0])
			f := evaluateURLObservation(t, r)
			if f.Status != NotObserved || f.Measurements.SampleCount != 1 || len(f.SourceIDs) != 1 || f.SourceIDs[0] != "h2" {
				t.Fatal("invalid POST authorized negative/positive; only verified GET may remain", f)
			}
		})
	}
	r = credentialObservationRequest()
	copy := r.Inputs[0].HTTP.Records[0]
	v := *copy.RequestVerification
	copy.RequestVerification = &v
	copy.Fields = map[string]string{"ordinary": "[redacted]"}
	copy.RequestVerification.FieldNames = HTTPRequestFieldNames(copy.Fields)
	r.Inputs[0].HTTP.Records = append(r.Inputs[0].HTTP.Records, copy)
	if f := evaluateURLObservation(t, r); f.Status != NotObserved || f.Measurements.SampleCount != 1 || f.Measurements.Values["conflicting_request_groups"] != 1 {
		t.Fatal("same request conflicting field inventories survived", f)
	}
	// Old URL-only markers remain sufficient for the URL fact, and cannot
	// independently authorize a credential-field observation.
	r = urlObservationRequest()
	if f := evaluateURLObservation(t, r); f.Status != NotObserved || f.Measurements.SampleCount != 2 {
		t.Fatal("URL marker compatibility lost", f)
	}
	r.Facts = []FactID{"F_CRED_POST_STRUCTURE"}
	if f := evaluateURLObservation(t, r); f.Status != Missing {
		t.Fatal("URL marker lent field authority", f)
	}
}
