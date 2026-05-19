package nodeapi

import (
	"encoding/json"
	"testing"
)

func TestValidRuleJSONRaw(t *testing.T) {
	if _, ok := validRuleJSONRaw(""); ok {
		t.Fatal("empty should be rejected")
	}
	if _, ok := validRuleJSONRaw("   "); ok {
		t.Fatal("whitespace should be rejected")
	}
	raw, ok := validRuleJSONRaw(`{"enabled":true}`)
	if !ok || !json.Valid(raw) {
		t.Fatalf("valid json expected, got ok=%v raw=%q", ok, raw)
	}
	if _, ok := validRuleJSONRaw(`{invalid`); ok {
		t.Fatal("invalid json should be rejected")
	}
}

func TestMarshalRulesResponse(t *testing.T) {
	ruleMap := map[string]json.RawMessage{
		"engine/availability": mustRaw(t, `{"enabled":true}`),
	}
	payload, err := json.Marshal(struct {
		Rules map[string]json.RawMessage `json:"rules"`
	}{Rules: ruleMap})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("expected non-empty payload")
	}
}

func mustRaw(t *testing.T, s string) json.RawMessage {
	t.Helper()
	raw, ok := validRuleJSONRaw(s)
	if !ok {
		t.Fatalf("invalid test raw: %q", s)
	}
	return raw
}
