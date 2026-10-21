package service

import "testing"

func TestProviderObservedDomainMatchesIOC(t *testing.T) {
	for _, tc := range []struct {
		name, observed, ioc string
		want                bool
	}{
		{"exact", "lsax.org", "lsax.org", true},
		{"real_parent_ioc", "zz-direct-test.oob.lsax.org", "lsax.org", true},
		{"case_insensitive", "ZZ-Direct-Test.OOB.LSAX.ORG", "LsAx.OrG", true},
		{"terminal_root_dot", "zz-direct-test.oob.lsax.org.", "lsax.org.", true},
		{"producer_surrounding_space", " \tzz-direct-test.oob.LSAX.org. ", " lsax.org. ", true},
		{"subdomain_ioc", "x.oob.lsax.org", "oob.lsax.org", true},
		{"underscore_label_not_reinterpreted", "_service._tcp.lsax.org", "lsax.org", true},
		{"plain_suffix_without_label_boundary", "evillsax.org", "lsax.org", false},
		{"hyphen_concatenation", "evil-lsax.org", "lsax.org", false},
		{"ioc_followed_by_attacker_domain", "lsax.org.evil.example", "lsax.org", false},
		{"label_postfix", "a.lsax.org-evil", "lsax.org", false},
		{"other_domain", "x.lsax.net", "lsax.org", false},
		{"relationship_not_reversed", "lsax.org", "x.lsax.org", false},
		{"url_observation", "https://zz-direct-test.oob.lsax.org", "lsax.org", false},
		{"url_ioc", "zz-direct-test.oob.lsax.org", "https://lsax.org", false},
		{"url_path_suffix", "https://evil.example/lsax.org", "lsax.org", false},
		{"userinfo_concatenation", "evil@zz-direct-test.oob.lsax.org", "lsax.org", false},
		{"port_not_a_question_name", "zz-direct-test.oob.lsax.org:53", "lsax.org", false},
		{"query_concatenation", "evil?x=zz-direct-test.oob.lsax.org", "lsax.org", false},
		{"fragment_concatenation", "evil#zz-direct-test.oob.lsax.org", "lsax.org", false},
		{"escaped_separator", "evil%2f.zz-direct-test.oob.lsax.org", "lsax.org", false},
		{"backslash_concatenation", "evil\\zz-direct-test.oob.lsax.org", "lsax.org", false},
		{"bracket_concatenation", "[evil].lsax.org", "lsax.org", false},
		{"embedded_space", "evil name.lsax.org", "lsax.org", false},
		{"embedded_newline", "evil\r\n.lsax.org", "lsax.org", false},
		{"embedded_nul", "evil\x00.lsax.org", "lsax.org", false},
		{"empty_observation", "", "lsax.org", false},
		{"empty_ioc", "lsax.org", "", false},
		{"root_only_ioc", "lsax.org", ".", false},
		{"leading_empty_label", ".lsax.org", "lsax.org", false},
		{"interior_empty_label", "evil..lsax.org", "lsax.org", false},
		{"do_not_trim_multiple_dots", "lsax.org..", "lsax.org", false},
		{"malformed_ioc", "x.lsax.org", "lsax..org", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerObservedDomainMatchesIOC(tc.observed, tc.ioc); got != tc.want {
				t.Fatalf("observed=%q ioc=%q got=%v want=%v", tc.observed, tc.ioc, got, tc.want)
			}
		})
	}
}
