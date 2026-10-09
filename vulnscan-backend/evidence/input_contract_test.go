package evidence

import "testing"

func TestInputContractsCoverExecutableRegistries(t *testing.T) {
	if len(SupportedFacts()) != 59 || len(SemanticInputContracts()) != 23 {
		t.Fatal("unexpected registry size")
	}
	for _, id := range SupportedFacts() {
		inputs := FactInputs(id)
		if len(inputs) == 0 {
			t.Fatalf("fact lacks input contract: %s", id)
		}
		inputs[0] = "mutated"
		if FactInputs(id)[0] == "mutated" {
			t.Fatal("mutable registry")
		}
	}
	for _, slot := range SemanticInputContracts() {
		if len(slot.MaterialKinds) == 0 {
			t.Fatalf("slot lacks contract: %s", slot.Slot.String())
		}
	}
	if FactInputs("unknown") != nil {
		t.Fatal("unknown fact silently assigned inputs")
	}
}
