package evidence

import (
	"crypto/x509"
	"strings"
)

func certificateNameMatches(host, name string) bool {
	host = strings.ToLower(host)
	name = strings.ToLower(name)
	if host == name {
		return true
	}
	if strings.HasPrefix(name, "*.") {
		suffix := strings.TrimPrefix(name, "*.")
		return strings.HasSuffix(host, "."+suffix) && strings.Count(host, ".") == strings.Count(suffix, ".")+1
	}
	return false
}
func (e *Engine) tlsFact(f Finding, g *observations) Finding {
	if g.input == nil || g.input.TLS == nil {
		return absent(f, MissingInput)
	}
	d := g.input.TLS
	dependency(&f, "tls", d.Provenance)
	if !provenance(d.Provenance) || !d.Complete || len(d.Records) == 0 {
		return absent(f, UnverifiedCoverage)
	}
	refs := append([]string(nil), d.SourceIDs...)
	matches := 0
	for _, r := range d.Records {
		if r.SourceID == "" || r.Time.IsZero() {
			return absent(f, MissingInput)
		}
		refs = append(refs, r.SourceID)
		switch f.FactID {
		case "F_TLS_SNI_MISMATCH":
			if r.SNI == "" || len(r.CertificateNames) == 0 || !d.ExceptionsVerified {
				return absent(f, MissingInput)
			}
			exception := false
			for _, pattern := range d.CDNExceptions {
				if certificateNameMatches(r.SNI, pattern) {
					exception = true
				}
			}
			if exception {
				continue
			}
			ok := false
			for _, name := range r.CertificateNames {
				if certificateNameMatches(r.SNI, name) {
					ok = true
				}
			}
			if !ok {
				matches++
			}
		case "F_TLS_CERT_ANOMALY":
			if !d.IssuersVerified || (len(r.CertificatesDER) == 0 && (!r.ChainVerified || r.NotBefore.IsZero() || r.NotAfter.IsZero() || r.Issuer == "")) {
				return absent(f, MissingInput)
			}
			// If DER and explicit trust anchors are supplied, verify the chain here.
			chainValid := r.ChainValid
			notBefore, notAfter, issuer := r.NotBefore, r.NotAfter, r.Issuer
			if len(r.CertificatesDER) > 0 {
				if len(d.TrustRootsDER) == 0 {
					return absent(f, MissingInput)
				}
				certs := []*x509.Certificate{}
				for _, der := range r.CertificatesDER {
					cert, err := x509.ParseCertificate(der)
					if err != nil {
						return absent(f, MissingInput)
					}
					certs = append(certs, cert)
				}
				notBefore, notAfter, issuer = certs[0].NotBefore, certs[0].NotAfter, certs[0].Issuer.String()
				roots := x509.NewCertPool()
				for _, der := range d.TrustRootsDER {
					cert, err := x509.ParseCertificate(der)
					if err != nil {
						return absent(f, MissingInput)
					}
					roots.AddCert(cert)
				}
				intermediate := x509.NewCertPool()
				for _, cert := range certs[1:] {
					intermediate.AddCert(cert)
				}
				_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediate, CurrentTime: r.Time, DNSName: r.SNI})
				chainValid = err == nil
			}
			if !chainValid || r.Time.Before(notBefore) || r.Time.After(notAfter) || !authorized(issuer, d.TrustedIssuers) {
				matches++
			}
		case "F_TLS_JA_MISMATCH":
			if !d.FingerprintsVerified || r.Fingerprint == "" || r.UserAgent == "" {
				return absent(f, MissingInput)
			}
			client, known := d.FingerprintClients[r.Fingerprint]
			if !known {
				return absent(f, MissingInput)
			}
			browser := strings.Contains(r.UserAgent, "Mozilla/")
			if browser && !strings.EqualFold(client, "browser") {
				matches++
			}
		}
	}
	return finish(f, matches > 0, map[string]float64{"tls_anomalies": float64(matches)}, refs...)
}
