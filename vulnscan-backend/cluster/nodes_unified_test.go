package cluster

import (
	"encoding/json"
	"math"
	"testing"
)

func TestUnifiedNode_JSONRejectsNaN(t *testing.T) {
	n := UnifiedNode{ID: "local", CPUUsage: math.NaN(), HealthScore: 100}
	_, err := json.Marshal(n)
	if err == nil {
		t.Fatal("expected json.Marshal error for NaN cpu_usage")
	}
}

func TestSanitizeFloat(t *testing.T) {
	if sanitizeFloat(math.NaN()) != 0 {
		t.Fatal("NaN should become 0")
	}
	if sanitizeFloat(12.5) != 12.5 {
		t.Fatal("normal float unchanged")
	}
}

func TestUnifiedNode_JSONWithSanitizedNaN(t *testing.T) {
	n := UnifiedNode{ID: "local", CPUUsage: sanitizeFloat(math.NaN()), HealthScore: 100}
	if _, err := json.Marshal(n); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}
