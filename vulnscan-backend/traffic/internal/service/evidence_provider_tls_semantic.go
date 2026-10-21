package service

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/gopacket/layers"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Only the immutable trigger frame can prove this SNI. Flow app hints and
// neighboring/exchange packets cannot turn ACKs or partial Hellos into one.
func providerVerifiedClientHelloSNI(h store.Hit, current map[string]any, input *evidence.Input, assets []domain.Asset) string {
	if input.Window == nil || h.OccurredAt.Before(input.Window.Start) || !h.OccurredAt.Before(input.Window.End) {
		return ""
	}
	// reportVerifyDatagram derives preview fields for legacy consumers. Check
	// original representations so such derivation cannot hide a source conflict.
	m := map[string]any{}
	d := json.NewDecoder(strings.NewReader(string(h.Raw)))
	d.UseNumber()
	if d.Decode(&m) != nil {
		return ""
	}
	scope, _, _, ok := snapshotScope(m, assets)
	if !ok || scope != input.Scope || !strings.EqualFold(asString(m["protocol"]), "tcp") {
		return ""
	}
	packet := nestedMap(m, "raw_packet")
	if truncated, _ := packet["capture_truncated"].(bool); truncated {
		return ""
	}
	at, err := time.Parse(time.RFC3339Nano, asString(packet["capture_time"]))
	if err != nil || !at.Equal(h.OccurredAt) {
		return ""
	}
	if usec, present := packet["capture_time_usec"]; present {
		n, valid := strictUint(usec)
		if !valid || h.OccurredAt.UnixMicro() < 0 || n != uint64(h.OccurredAt.UnixMicro()) {
			return ""
		}
	}
	m[snapshotParseContextKey] = snapshotParsing(current)
	p, err := snapshotDecodeFrame(m, asString(packet["packet_hex"]))
	if err != nil || p.ErrorLayer() != nil {
		return ""
	}
	complete := false
	if ip, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		complete = len(ip.Contents)+len(ip.Payload) == int(ip.Length) && ip.FragOffset == 0 && ip.Flags&layers.IPv4MoreFragments == 0
	}
	if ip, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		complete = len(ip.Payload) == int(ip.Length) && p.Layer(layers.LayerTypeIPv6Fragment) == nil
	}
	tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !complete || !ok || tcp.RST || !tcp.ACK {
		return ""
	}
	for _, key := range []string{"captured_length", "wire_length"} {
		if v, present := packet[key]; present {
			n, valid := strictUint(v)
			if !valid || n != uint64(len(p.Data())) {
				return ""
			}
		}
	}
	if _, why := snapshotFramePayload(packet, m, input); why != "" {
		return ""
	}
	sni := providerCompleteClientHelloSNI(tcp.Payload)
	if sni == "" || !utf8.ValidString(sni) || !providerObservedDomainMatchesIOC(sni, sni) {
		return ""
	}
	if hint := asString(nestedMap(m, "app")["tls_sni"]); hint != "" && !strings.EqualFold(strings.TrimSuffix(hint, "."), strings.TrimSuffix(sni, ".")) {
		return ""
	}
	return sni
}

// Require one complete handshake/record and consume every extension, including
// extensions after server_name. A readable early SNI is not a framing proof.
func providerCompleteClientHelloSNI(b []byte) string {
	if len(b) < 9 || b[0] != 22 || b[1] != 3 || b[2] > 4 || int(binary.BigEndian.Uint16(b[3:5])) != len(b)-5 || b[5] != 1 {
		return ""
	}
	b = b[5:]
	if len(b) < 39 || int(b[1])<<16|int(b[2])<<8|int(b[3]) != len(b)-4 {
		return ""
	}
	i := 38
	if b[i] > 32 {
		return ""
	}
	i += 1 + int(b[i])
	if i+2 > len(b) {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b[i : i+2]))
	if n < 2 || n%2 != 0 {
		return ""
	}
	i += 2 + n
	if i >= len(b) || b[i] == 0 {
		return ""
	}
	i += 1 + int(b[i])
	if i+2 > len(b) || i+2+int(binary.BigEndian.Uint16(b[i:i+2])) != len(b) {
		return ""
	}
	i += 2
	sni := ""
	seen := map[uint16]bool{}
	for i < len(b) {
		if i+4 > len(b) {
			return ""
		}
		typ, size := binary.BigEndian.Uint16(b[i:i+2]), int(binary.BigEndian.Uint16(b[i+2:i+4]))
		i += 4
		if seen[typ] || i+size > len(b) {
			return ""
		}
		seen[typ] = true
		v := b[i : i+size]
		i += size
		if typ == 0 {
			if len(v) < 6 || int(binary.BigEndian.Uint16(v[:2])) != len(v)-2 || v[2] != 0 || int(binary.BigEndian.Uint16(v[3:5])) != len(v)-5 {
				return ""
			}
			sni = string(v[5:])
		}
	}
	return sni
}
