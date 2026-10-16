//go:build ignore

// Run from vulnscan-backend: go run ../tools/evidence-contract-catalog.go <output.json>
// Reads only the executable registry. No database or model access.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"vulnscan-backend/evidence"
)

func main() {
	if len(os.Args)!=2 {panic("output JSON path required")}
	output:=map[string]any{
		"contract_version":evidence.ContractVersion,"fact_version":evidence.RuleVersion,"semantic_version":evidence.SemanticVersion,
		"facts":evidence.Definitions(),"slots":evidence.SemanticDefinitions(),
		"phase_one_facts":evidence.PhaseOneFacts(),"phase_one_slots":evidence.PhaseOneSlots(),"phase_one_units":evidence.PhaseOneDefinitions(),
		"acceptance_boundary":"82 registered contracts; controlled tests are not production or semantic-accuracy certification",
	}
	data,err:=json.MarshalIndent(output,"","  ");if err!=nil{panic(err)}
	if err=os.WriteFile(os.Args[1],append(data,'\n'),0600);err!=nil{panic(err)}
	fmt.Printf("wrote %d facts and %d semantic slots to %s\n",len(evidence.Definitions()),len(evidence.SemanticDefinitions()),os.Args[1])
}
