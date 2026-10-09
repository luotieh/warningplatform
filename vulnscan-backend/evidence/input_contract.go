package evidence

// FactInputs describes the rule's data families for coverage diagnostics.
// Per-field validation and sample/baseline/policy gates live in the rule itself.
// Return values are copies; callers cannot mutate the shared registry.
func FactInputs(id FactID) []string {
	if !supported(id) {
		return nil
	}
	var inputs []string
	if groupRule(id) {
		inputs = []string{"group_membership", "group_observations"}
	} else {
		switch id {
		case BeaconPeriodic, MultiDayPersist, "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW", "F_RATE_BURST", "F_RATE_RAMP":
			inputs = []string{"time_series", "capture_quality"}
		case "F_DNS_HIGH_ENTROPY", "F_DNS_ENCODED_LABEL", "F_DGA_LEXICAL", "F_NXDOMAIN_CLUSTER", "F_FAILED_TO_ACTIVE":
			inputs = []string{"dns_records"}
		case "F_HTTP_ENDPOINT_REPEAT", "F_HTTP_FIELD_ENCODING", "F_HTTP_UA_RARITY", "F_HTTP_SIZE_STABILITY", "F_URL_ODD_AUTHORITY", "F_URL_HOMOGLYPH", "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR", "F_CRED_POST_STRUCTURE", "F_FORM_CROSSSITE", "F_REDIRECT_CHAIN", "F_MULTI_REDIRECT_CHAIN":
			inputs = []string{"http_records"}
		case "F_LONG_LOW_SESSION":
			inputs = []string{"verified_sessions", "time_series", "capture_quality"}
		case "F_INDEPENDENT_RULE_CORROB", "F_INDEPENDENT_INTEL_CORROB", "F_IOC_TYPE_CORROB":
			inputs = []string{"independent_rule_and_intel_metadata"}
		case "F_TLS_SNI_MISMATCH", "F_TLS_CERT_ANOMALY", "F_TLS_JA_MISMATCH":
			inputs = []string{"tls_records", "tls_trust_and_fingerprint_registry"}
		case "F_HIST_EXERCISE", "F_EXCL_SCAN_TASK", "F_EXCL_INFRA_ROLE":
			inputs = []string{"authorization_records"}
		case "F_HIST_ASSET_IOC_RECURRENCE", "F_HIST_GROUP_RECURRENCE", "F_HIST_INFRA_PERSISTENCE", "F_HIST_SCHEDULE_MATCH", "F_HIST_MULTI_IOC_SIEGE", "F_HIST_STAGE_PROGRESSION", "F_HIST_COORD_PARAM_MATCH", "F_IOC_NOVELTY", "F_DST_NOVELTY":
			inputs = []string{"history"}
		default:
			inputs = []string{"network_records"}
		}
	}
	switch id {
	case "F_RATE_BURST", "F_DNS_HIGH_ENTROPY", "F_DGA_LEXICAL", "F_NXDOMAIN_CLUSTER", "F_GROUP_NXDOMAIN_CLUSTER", "F_SHARED_DOMAIN_CLUSTER", "F_HTTP_FIELD_ENCODING", "F_HTTP_UA_RARITY", "F_HTTP_SIZE_STABILITY", "F_RARE_PORT", "F_INFRA_RARITY", "F_FANOUT_SINGLE_SRC", "F_CONN_FAIL_RATE", "F_SHARED_ENDPOINT", "F_HIST_MULTI_IOC_SIEGE":
		inputs = append(inputs, "baselines")
	}
	switch id {
	case "F_URL_HOMOGLYPH", "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR":
		inputs = append(inputs, "brand_registry")
	case "F_HIST_STAGE_PROGRESSION", "F_HIST_COORD_PARAM_MATCH":
		inputs = append(inputs, "campaign_and_stage_proofs")
	case "F_PROTOCOL_PORT_MISMATCH":
		inputs = append(inputs, "service_registry")
	case "F_DGA_LEXICAL":
		inputs = append(inputs, "dns_lexical_corpus")
	case "F_INFRA_RARITY":
		inputs = append(inputs, "infrastructure_registry")
	case "F_FIRST_VISIT_CLUSTER":
		inputs = append(inputs, "history")
	}
	return append([]string(nil), inputs...)
}

func AssetWideFact(id FactID) bool {
	switch id {
	case "F_PORT_SEQUENCE", "F_FANOUT_SINGLE_SRC", "F_DNS_HIGH_ENTROPY", "F_NXDOMAIN_CLUSTER", "F_FAILED_TO_ACTIVE", "F_DGA_LEXICAL", "F_HIST_MULTI_IOC_SIEGE":
		return true
	}
	return false
}

type SemanticInputContract struct {
	Slot          SlotKey  `json:"slot"`
	MaterialKinds []string `json:"material_kinds"`
	AllFacts      []FactID `json:"all_facts"`
	AnyFacts      []FactID `json:"any_facts"`
}

// Exposes prerequisites from the executable catalog instead of duplicating 23
// semantic definitions in a traffic-specific adapter.
func SemanticInputContracts() []SemanticInputContract {
	out := make([]SemanticInputContract, 0, len(semanticSpecs))
	for _, spec := range semanticSpecs {
		out = append(out, SemanticInputContract{Slot: spec.Key, MaterialKinds: append([]string(nil), spec.Kinds...), AllFacts: append([]FactID(nil), spec.AllFacts...), AnyFacts: append([]FactID(nil), spec.AnyFacts...)})
	}
	return out
}
