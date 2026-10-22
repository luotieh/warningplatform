package service

// Frozen v0.2 mapping: actual stable keys only. Unknown keys never earn points.
func reportScoreProfiles() []reportScoreProfile {
	r := func(weight, cap float64, behavior, direct bool, keys ...string) reportScoreRow {
		return reportScoreRow{keys: keys, weight: weight, cap: cap, behavior: behavior, direct: direct}
	}
	combo := func(id string, w float64, independent bool, left, right []string) reportScoreCombo {
		return reportScoreCombo{id: id, weight: w, independent: independent, left: left, right: right}
	}
	keys := func(s ...string) []string { return s }
	intel := "I:ioc_background"
	period := keys("F_BEACON_PERIODIC", "F_BEACON_JITTER", "F_FIXED_DAILY_WINDOW")
	history := keys("F_HIST_ASSET_IOC_RECURRENCE", "F_MULTI_DAY_PERSIST")
	control := keys("S:S01/c2.command_intent/", "S:S02/c2.command_exchange/", "S:S13/payload.decoded_intent/command", "S:S04/c2.dns_encoded_intent/")
	timeRow := r(.9, 1.1, true, false, append(append([]string{}, period...), "F_HIST_SCHEDULE_MATCH")...)
	timeRow.limit = "time"
	night := r(.25, 1.1, false, false, "O:schedule")
	night.limit = "time"
	c2 := reportScoreProfile{kind: "c2_related", rows: []reportScoreRow{
		r(.8, .8, false, false, intel), timeRow, night, r(.55, .55, false, false, history...),
		r(.9, 1.1, true, false, "F_HTTP_ENDPOINT_REPEAT", "F_DNS_ENCODED_LABEL", "F_LONG_LOW_SESSION", "F_HTTP_FIELD_ENCODING", "F_HTTP_UA_RARITY", "F_HTTP_SIZE_STABILITY", "F_DGA_LEXICAL", "F_NXDOMAIN_CLUSTER", "F_FAILED_TO_ACTIVE"),
		r(2.6, 2.6, true, true, control...),
	}, combos: []reportScoreCombo{
		combo("c2.period_history", .45, true, period, history),
		combo("c2.dns_control", .8, false, keys("F_DNS_ENCODED_LABEL"), keys("S:S04/c2.dns_encoded_intent/")),
		combo("c2.control_independent", 1.2, true, control, append(append([]string{}, period...), history...)),
	}}
	coord := keys("F_TIME_COORDINATION", "F_COORD_FANOUT")
	botnet := reportScoreProfile{kind: "botnet_related", rows: []reportScoreRow{
		r(.7, .7, false, false, intel), r(.6, .8, false, false, "F_MULTI_ASSET_IOC", "F_MULTI_ASSET_DIST", "F_SHARED_ENDPOINT", "F_SHARED_DOMAIN_CLUSTER", "F_GROUP_NXDOMAIN_CLUSTER"),
		r(1.3, 1.5, true, false, append(append([]string{}, coord...), "F_FIRST_VISIT_CLUSTER")...),
		r(.7, .7, false, false, "F_COORD_PATTERN_RECURRENCE", "F_HIST_GROUP_RECURRENCE", "F_HIST_INFRA_PERSISTENCE", "F_HIST_COORD_PARAM_MATCH"),
		r(.8, .8, false, false, "F_INFECTION_CHAIN"), r(2.6, 2.6, false, true, control[:3]...),
	}, combos: []reportScoreCombo{
		combo("botnet.shared_coord", .6, true, keys("F_SHARED_ENDPOINT"), keys("F_TIME_COORDINATION")),
		combo("botnet.coord_history", .8, true, coord, keys("F_COORD_PATTERN_RECURRENCE", "F_HIST_GROUP_RECURRENCE")),
		combo("botnet.coord_control", 1.3, true, coord, control[:3]),
	}}
	deception := keys("F_URL_HOMOGLYPH", "F_URL_BRAND_SUBDOMAIN_TRICK", "F_BRAND_IMPOSTOR", "S:S05/phishing.deception/", "S:S12/phishing.deception/brand_semantic_impostor")
	deceive := r(1.4, 1.6, true, false, deception...)
	deceive.limit = "deception"
	odd := r(.2, 1.6, false, false, "F_URL_ODD_AUTHORITY")
	odd.limit = "deception"
	phishing := reportScoreProfile{kind: "phishing_related", rows: []reportScoreRow{
		r(.8, .8, false, false, intel), deceive, odd,
		r(.7, .9, false, false, "F_CRED_POST_STRUCTURE", "F_FORM_CROSSSITE", "S:S06/phishing.credential_action/"),
		r(.5, .5, false, false, "F_REDIRECT_CHAIN", "F_MULTI_REDIRECT_CHAIN"), r(.25, .25, false, false, history...),
	}, combos: []reportScoreCombo{
		combo("phishing.deceive_collect", 1.5, false, keys("S:S05/phishing.deception/", "S:S12/phishing.deception/brand_semantic_impostor"), keys("S:S06/phishing.credential_action/")),
		combo("phishing.deceive_submit", .7, false, keys("F_BRAND_IMPOSTOR", "F_URL_BRAND_SUBDOMAIN_TRICK"), keys("F_REDIRECT_CHAIN")),
		// Exact domain-to-intelligence matching has no dedicated verified flag in the current report projection; no guessed combo.
	}}
	scanning := reportScoreProfile{kind: "scanning_related", rows: []reportScoreRow{
		r(.6, .6, false, false, intel), r(1.2, 1.5, true, false, "F_FANOUT_SINGLE_SRC", "F_PORT_SEQUENCE", "F_CONN_FAIL_RATE"), r(.5, .5, false, false, "F_RATE_BURST", "F_RATE_RAMP"), r(.4, .4, false, false, "F_PROTOCOL_PORT_MISMATCH"),
	}, combos: []reportScoreCombo{
		combo("scan.fanout_ports", .8, true, keys("F_FANOUT_SINGLE_SRC"), keys("F_PORT_SEQUENCE")),
		combo("scan.shape_failure", .4, true, keys("F_FANOUT_SINGLE_SRC", "F_PORT_SEQUENCE"), keys("F_CONN_FAIL_RATE")),
	}}
	exfil := reportScoreProfile{kind: "exfiltration_related", rows: []reportScoreRow{
		r(.7, .7, false, false, intel), r(.5, .5, false, false, "F_DNS_HIGH_ENTROPY", "F_HTTP_FIELD_ENCODING", "F_DNS_ENCODED_LABEL"), r(2.6, 2.6, true, true, "S:S07/exfil.sensitive_upload/"), r(.8, .8, true, false, "S:S08/exfil.chunk_sequence/"),
	}, combos: []reportScoreCombo{combo("exfil.upload_chunks", 1, true, keys("S:S07/exfil.sensitive_upload/"), keys("S:S08/exfil.chunk_sequence/"))}}
	exploit := reportScoreProfile{kind: "exploit_related", rows: []reportScoreRow{
		r(.7, .7, false, false, intel), r(.5, .5, false, false, "F_PROTOCOL_PORT_MISMATCH"), r(2.6, 2.6, true, true, "S:S09/exploit.payload_intent/"), r(.7, .7, false, false, "S:S10/protocol.response_meaning/"),
	}, combos: []reportScoreCombo{combo("exploit.payload_response", .8, false, keys("S:S09/exploit.payload_intent/"), keys("S:S10/protocol.response_meaning/"))}}
	mining := reportScoreProfile{kind: "mining_related", rows: []reportScoreRow{r(.7, .7, false, false, intel), r(1.4, 1.6, true, false, "S:S11/mining.protocol_intent/"), r(.4, .4, false, false, history...)}}
	contact := reportScoreProfile{kind: "suspicious_contact", rows: []reportScoreRow{r(.7, .7, false, false, intel), r(.2, .2, false, false, "F_RARE_PORT", "F_DST_NOVELTY", "F_INFRA_RARITY", "F_HIST_MULTI_IOC_SIEGE"), r(.25, .25, false, false, "F_RATE_BURST", "F_RATE_RAMP")}}
	profiles := []reportScoreProfile{botnet, c2, exfil, exploit, mining, phishing, scanning, contact}
	for j := range profiles {
		if profiles[j].kind != "suspicious_contact" {
			profiles[j].rows = append(profiles[j].rows, r(.4, .4, false, false, "F_INDEPENDENT_RULE_CORROB"))
		}
	}
	return profiles
}
