package service

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"vulnscan-backend/evidence"
)

// A question can contain its encoded label at any position. Keep one exact
// label as one proposition; multiple readable labels require a separate
// disambiguation contract and are deliberately not concatenated or selected.
// This only transforms an already verified DNS observation, without another
// packet decode, source read, query or model call.
func addProviderDNSHexMaterials(s *evidence.SemanticSubject, domain evidence.SemanticMaterial, makeMaterial semanticMaterialFactory, p evidence.Provenance) {
	if !p.Verified || !p.Complete || domain.Truncated || domain.Text == "" {
		return
	}
	index := -1
	var candidate, plain, selectedEncoding string
	for n, label := range strings.Split(strings.TrimSuffix(domain.Text, "."), ".") {
		// The DNS fact contract accepts at least four decoded bytes. DNS labels
		// themselves bound the work; no searching arbitrary substrings.
		if len(label) < 8 || len(label) > 63 {
			continue
		}
		encoding := "hex"
		decoded, err := hex.DecodeString(label)
		if err != nil || len(decoded) < 4 {
			encoding = "base32"
			base := base32.StdEncoding.WithPadding(base32.NoPadding)
			decoded, err = base.DecodeString(strings.ToUpper(label))
			if err == nil && !strings.EqualFold(base.EncodeToString(decoded), label) {
				continue
			}
		}
		if err != nil || len(decoded) < 4 || !utf8.Valid(decoded) || strings.IndexFunc(string(decoded), func(r rune) bool {
			return r < 32 && r != '\n' && r != '\r' && r != '\t'
		}) >= 0 {
			continue
		}
		if index >= 0 {
			return
		}
		index, candidate, plain = n, label, string(decoded)
		selectedEncoding = encoding
	}
	if index < 0 {
		return
	}
	// Preserve the delivered material identity for the first-label hex case
	// already supported by saved model transcripts. The scan above still rejects
	// ambiguous questions before this compatibility path can select a label.
	if index == 0 && selectedEncoding == "hex" && len(candidate) >= 12 {
		addSemanticDecodeMaterials(s, candidate, []string{domain.ID}, makeMaterial, p)
		return
	}
	path := fmt.Sprintf("dns.question.labels[%d]", index)
	encoded := makeMaterial(s, "encoded_payload", candidate, path, p, true)
	decoded := makeMaterial(s, "decoded_payload", plain, path+".decoded", p, true)
	proof := makeMaterial(s, "decode", "Validated single-layer "+selectedEncoding+" from one DNS question label; decoding does not establish malicious intent", path+".decode", p, true)
	proof.DecodeSteps = []evidence.SemanticDecodeStep{{Encoding: selectedEncoding, InputID: encoded.ID, OutputID: decoded.ID}}
	context := makeMaterial(s, "operation_context", "Decoded from this saved DNS question", path, p, true)
	context.RelatedIDs = []string{decoded.ID}
	for n := range s.Materials {
		if s.Materials[n].ID == domain.ID {
			s.Materials[n].RelatedIDs = append(s.Materials[n].RelatedIDs, encoded.ID, decoded.ID)
		}
	}
	s.Materials = append(s.Materials, encoded, decoded, proof, context)
}
