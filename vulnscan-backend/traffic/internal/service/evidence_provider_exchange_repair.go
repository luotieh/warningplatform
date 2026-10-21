package service

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const providerExchangeCacheKey = "_provider_verified_http_exchange"
const maxProviderExchangePackets = 512

// This is an offline derivation, never a replacement for the stored Raw. The
// synthetic payload maps deliberately have no packet_hex: a reassembled message
// must not masquerade as one captured datagram.
type providerHTTPExchange struct {
	Request, Response map[string]any
	RequestMap        map[string]any
	RequestTime       time.Time
	RequestProblem    string
	ResponseProblem   string
	FrameDecodes      int64
	FramingParses     int64
	requestSide       *providerExchangeSide
}

type providerExchangeSide struct {
	payload     []byte
	src, dst    string
	sp, dp      uint16
	seq, ack    uint32
	first, last time.Time
}

type providerExchangeFragment struct {
	payload  []byte
	seq, ack uint32
	at       time.Time
}

// Cache even a rejected source so all consumers share one bounded decision.
// Presence of response_status, context_final or a revision is never proof of
// complete bytes. Only the frames, reconstruction and HTTP framing establish it.
func providerVerifiedHTTP(m map[string]any) *providerHTTPExchange {
	if cached, ok := m[providerExchangeCacheKey]; ok {
		x, _ := cached.(*providerHTTPExchange)
		return x
	}
	m[providerExchangeCacheKey] = (*providerHTTPExchange)(nil)
	ex := nestedMap(m, "exchange")
	if len(ex) == 0 || asString(m["session_id"]) == "" || asString(m["transaction_id"]) == "" {
		return nil
	}
	x := &providerHTTPExchange{}
	m[providerExchangeCacheKey] = x
	request, reason := providerVerifyExchangeSide(nestedMap(ex, "request"), m, &x.FrameDecodes)
	if reason != "" || request == nil {
		x.RequestProblem = reason
		return x
	}
	x.FramingParses++
	if !providerHTTPFramed(request.payload, false) {
		x.RequestProblem = "http_request_framing_unverified"
		return x
	}
	x.requestSide, x.RequestTime = request, request.first
	x.Request = providerExchangePayload(request)
	x.RequestMap = make(map[string]any, len(m))
	for key, value := range m {
		if key != snapshotParseContextKey && key != providerExchangeCacheKey {
			x.RequestMap[key] = value
		}
	}
	x.RequestMap["src_ip"], x.RequestMap["dst_ip"] = request.src, request.dst
	x.RequestMap["src_port"], x.RequestMap["dst_port"] = uint64(request.sp), uint64(request.dp)
	// The request ID helper must see these verified sequence bytes, not the
	// triggering response/ACK's sequence or a legacy first-fragment projection.
	x.RequestMap["raw_packet"] = x.Request
	response, why := providerVerifyExchangeSide(nestedMap(ex, "response"), m, &x.FrameDecodes)
	x.ResponseProblem = why
	if response != nil && why == "" {
		switch {
		case response.src != request.dst || response.dst != request.src || response.sp != request.dp || response.dp != request.sp:
			x.ResponseProblem = "exchange_response_direction_conflict"
		case response.first.Before(request.first):
			x.ResponseProblem = "exchange_response_time_conflict"
		case request.seq+uint32(len(request.payload)) != response.ack || request.ack != response.seq:
			x.ResponseProblem = "http_pair_sequence_unverified"
		case !providerHTTPFramed(response.payload, true):
			x.ResponseProblem = "http_response_framing_unverified"
		default:
			x.Response = providerExchangePayload(response)
		}
	}
	m[providerExchangeCacheKey] = x
	return x
}

func providerExchangePayload(side *providerExchangeSide) map[string]any {
	return map[string]any{
		"payload_hex": hex.EncodeToString(side.payload), "capture_truncated": false,
		"tcp_seq": uint64(side.seq), "tcp_ack": uint64(side.ack),
		"capture_time": side.first.Format(time.RFC3339Nano),
	}
}

func providerVerifyExchangeSide(raw, m map[string]any, decodes *int64) (*providerExchangeSide, string) {
	if len(raw) == 0 {
		return nil, "exchange_side_missing"
	}
	if raw["truncated"] == true || raw["reassembly_incomplete"] == true {
		return nil, "exchange_side_incomplete"
	}
	hexText, ok := raw["reassembled_hex"].(string)
	if !ok || hexText == "" || len(hexText) > 2*maxEvidenceMessageBytes {
		return nil, "exchange_bytes_missing_or_oversized"
	}
	wanted, err := hex.DecodeString(hexText)
	if err != nil {
		return nil, "exchange_bytes_invalid"
	}
	packets, ok := raw["packets"].([]any)
	if !ok || len(packets) == 0 || len(packets) > maxProviderExchangePackets {
		return nil, "exchange_packets_missing_or_oversized"
	}
	side := &providerExchangeSide{}
	fragments := []providerExchangeFragment{}
	total := 0
	for _, entry := range packets {
		packet, ok := entry.(map[string]any)
		if !ok || packet["capture_truncated"] == true {
			return nil, "exchange_packet_truncated"
		}
		encoded := asString(packet["packet_hex"])
		total += len(encoded)
		if encoded == "" || total > 4*maxEvidenceMessageBytes {
			return nil, "exchange_packet_budget_exceeded"
		}
		frame, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, "exchange_packet_invalid"
		}
		p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		*decodes++
		if p.ErrorLayer() != nil {
			return nil, "exchange_packet_invalid"
		}
		complete, src, dst := false, "", ""
		if layer := p.Layer(layers.LayerTypeIPv4); layer != nil {
			ip := layer.(*layers.IPv4)
			src, dst = ip.SrcIP.String(), ip.DstIP.String()
			complete = len(ip.Contents)+len(ip.Payload) >= int(ip.Length) && ip.FragOffset == 0 && ip.Flags&layers.IPv4MoreFragments == 0
		}
		if layer := p.Layer(layers.LayerTypeIPv6); layer != nil {
			ip := layer.(*layers.IPv6)
			src, dst = ip.SrcIP.String(), ip.DstIP.String()
			complete = len(ip.Payload) >= int(ip.Length) && p.Layer(layers.LayerTypeIPv6Fragment) == nil
		}
		tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !complete || !ok || tcp.RST {
			return nil, "exchange_packet_incomplete_or_not_tcp"
		}
		if !providerExchangeTuple(m, src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort)) {
			return nil, "exchange_packet_flow_conflict"
		}
		if captured, present := packet["captured_length"]; present {
			n, valid := strictUint(captured)
			if !valid || n != uint64(len(frame)) {
				return nil, "exchange_packet_length_conflict"
			}
		}
		if wire, present := packet["wire_length"]; present {
			n, valid := strictUint(wire)
			if !valid || n != uint64(len(frame)) {
				return nil, "exchange_packet_length_conflict"
			}
		}
		if text, present := packet["payload_hex"].(string); present {
			body, err := hex.DecodeString(text)
			if err != nil || !bytes.Equal(body, tcp.Payload) {
				return nil, "exchange_packet_payload_conflict"
			}
		}
		for key, actual := range map[string]uint32{"tcp_seq": tcp.Seq, "tcp_ack": tcp.Ack} {
			if saved, present := packet[key]; present {
				n, valid := strictUint(saved)
				if !valid || n != uint64(actual) {
					return nil, "exchange_packet_sequence_conflict"
				}
			}
		}
		at, valid := providerExchangePacketTime(packet)
		if !valid {
			return nil, "exchange_packet_time_invalid"
		}
		if side.src == "" {
			side.src, side.dst, side.sp, side.dp = src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort)
		} else if side.src != src || side.dst != dst || side.sp != uint16(tcp.SrcPort) || side.dp != uint16(tcp.DstPort) {
			return nil, "exchange_side_direction_conflict"
		}
		if len(tcp.Payload) == 0 {
			continue
		}
		if !tcp.ACK {
			return nil, "exchange_packet_ack_missing"
		}
		seq := tcp.Seq
		if tcp.SYN {
			seq++
		}
		fragments = append(fragments, providerExchangeFragment{tcp.Payload, seq, tcp.Ack, at})
	}
	if len(fragments) == 0 {
		return nil, "exchange_payload_not_observed"
	}
	base := fragments[0].seq
	sort.SliceStable(fragments, func(i, j int) bool { return int32(fragments[i].seq-base) < int32(fragments[j].seq-base) })
	side.seq, side.ack = fragments[0].seq, fragments[0].ack
	reconstructed := []byte{}
	for _, f := range fragments {
		offset := int(uint32(f.seq - side.seq))
		if offset > len(reconstructed) || offset+len(f.payload) > maxEvidenceMessageBytes {
			return nil, "exchange_tcp_gap"
		}
		if f.ack != side.ack {
			return nil, "exchange_ack_changed_within_message"
		}
		for i, b := range f.payload {
			at := offset + i
			if at < len(reconstructed) {
				if reconstructed[at] != b {
					return nil, "exchange_tcp_overlap_conflict"
				}
			} else {
				reconstructed = append(reconstructed, b)
			}
		}
		if side.first.IsZero() || f.at.Before(side.first) {
			side.first = f.at
		}
		if side.last.IsZero() || f.at.After(side.last) {
			side.last = f.at
		}
	}
	if !bytes.Equal(reconstructed, wanted) {
		return nil, "exchange_reassembly_bytes_conflict"
	}
	for key, boundary := range map[string]time.Time{"capture_start_time_usec": side.first, "capture_end_time_usec": side.last} {
		if saved, present := raw[key]; present {
			n, valid := strictUint(saved)
			// Side counters may include an earlier ACK/SYN, but never exclude
			// observed message bytes. Packet timestamps remain the contact time.
			if !valid || n > uint64(^uint64(0)>>1) {
				return nil, "exchange_side_time_invalid"
			}
			t := time.UnixMicro(int64(n))
			if (key == "capture_start_time_usec" && t.After(boundary)) || (key == "capture_end_time_usec" && t.Before(boundary)) {
				return nil, "exchange_side_time_conflict"
			}
		}
	}
	side.payload = reconstructed
	return side, ""
}

func providerExchangePacketTime(packet map[string]any) (time.Time, bool) {
	var at time.Time
	if n, ok := strictUint(packet["capture_time_usec"]); ok && n > 0 && n <= uint64(^uint64(0)>>1) {
		at = time.UnixMicro(int64(n)).UTC()
	}
	if text := asString(packet["capture_time"]); text != "" {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || (!at.IsZero() && !parsed.Equal(at)) {
			return time.Time{}, false
		}
		at = parsed.UTC()
	}
	return at, !at.IsZero()
}

func providerExchangeTuple(m map[string]any, src, dst string, sp, dp uint16) bool {
	if !strings.EqualFold(firstNonEmpty(asString(m["protocol"]), asString(m["proto"])), "tcp") {
		return false
	}
	a, b := net.ParseIP(asString(m["src_ip"])), net.ParseIP(asString(m["dst_ip"]))
	ap, aok := strictUint(m["src_port"])
	bp, bok := strictUint(m["dst_port"])
	if a == nil || b == nil || !aok || !bok {
		return false
	}
	return a.Equal(net.ParseIP(src)) && b.Equal(net.ParseIP(dst)) && ap == uint64(sp) && bp == uint64(dp) || a.Equal(net.ParseIP(dst)) && b.Equal(net.ParseIP(src)) && ap == uint64(dp) && bp == uint64(sp)
}

func providerHTTPFramed(payload []byte, response bool) bool {
	r := bufio.NewReader(bytes.NewReader(payload))
	var body io.ReadCloser
	if response {
		msg, err := http.ReadResponse(r, nil)
		if err != nil {
			return false
		}
		body = msg.Body
		if msg.StatusCode < 200 || (msg.ContentLength < 0 && len(msg.TransferEncoding) == 0) {
			body.Close()
			return false
		}
	} else {
		msg, err := http.ReadRequest(r)
		if err != nil {
			return false
		}
		body = msg.Body
	}
	defer body.Close()
	content, err := io.ReadAll(io.LimitReader(body, maxEvidenceMessageBytes+1))
	if err != nil || len(content) > maxEvidenceMessageBytes {
		return false
	}
	_, err = r.Peek(1)
	return err == io.EOF
}

// Identity is byte/flow/sequence based, exactly like legacy contacts. The
// collector's transaction label is required for pairing but never counts hits.
func appendProviderExchangeContact(manifest *SnapshotEvidenceManifest, h store.Hit, m map[string]any, input evidence.Input, assets []domain.Asset, snap EvidenceSnapshot) {
	x := providerVerifiedHTTP(m)
	if x == nil || x.Request == nil || !providerExchangeInWindow(x, &input) || manifest.PhaseOne == nil || input.HTTP == nil {
		return
	}
	var request *evidence.HTTPRecord
	for i := range input.HTTP.Records {
		r := &input.HTTP.Records[i]
		if r.SourceID == h.ID && !r.Truncated && r.RawRequest == string(x.requestSide.payload) {
			request = r
			break
		}
	}
	if request == nil {
		return
	}
	ioc, field := providerStoredIOCField(m, "")
	s := x.requestSide
	switch ioc.Type {
	case "ip":
		if local, ok := registeredSnapshotAsset(assets, ioc.Value); ok && local == input.Scope.AssetID {
			return
		}
		if ioc.Value != s.src && ioc.Value != s.dst {
			return
		}
		field = "ipv4_or_ipv6.dst_ip"
		if ioc.Value == s.src {
			field = "ipv4_or_ipv6.src_ip"
		}
	case "domain":
		u, err := url.Parse(request.URL)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(ioc.Value, ".")) {
			return
		}
		field = "http.request.host"
	case "url":
		if request.URL != ioc.Value {
			return
		}
		field = "http.request.url"
	default:
		return
	}
	key := digest([]any{m["device_id"], s.src, s.dst, uint64(s.sp), uint64(s.dp), "request", s.seq, request.RawRequest})
	c := PhaseOneContact{ID: key, Kind: "complete_http_request", HitID: h.ID, Time: x.RequestTime, Scope: input.Scope, IOCType: ioc.Type, IOCValue: ioc.Value, Snapshot: phaseOneSnapshotSource(snap), TCP: &PhaseOneTCPContact{FlowID: digest([]any{input.Scope.DeviceID, s.src, s.dst, s.sp, s.dp}), Sequence: s.seq}}
	if start, err := time.Parse(time.RFC3339Nano, asString(nestedMap(m, "raw_packet")["session_start_time"])); err == nil && !start.IsZero() && !start.After(c.Time) {
		start = start.UTC()
		c.TCP.SessionStart = &start
		c.ID = digest([]any{c.ID, start})
	}
	// Legacy collection sees the triggering frame, which can be a response or
	// ACK carrying this transaction's request context. Replace only this hit's
	// HTTP projection with the verified request sequence/time. Never remove SYN,
	// DNS, another IOC/scope, or another hit's independently owned observation.
	kept := manifest.PhaseOne.Contacts[:0]
	for _, old := range manifest.PhaseOne.Contacts {
		if old.HitID == h.ID && old.Kind == c.Kind && old.Scope == c.Scope && old.IOCType == c.IOCType && old.IOCValue == c.IOCValue {
			continue
		}
		kept = append(kept, old)
	}
	manifest.PhaseOne.Contacts = kept
	duplicate := false
	for _, old := range kept {
		if old.ID == c.ID {
			duplicate = true
			break
		}
		// Opposite-direction hit projections can carry different legacy
		// session-start metadata. Equal verified request bytes, TCP sequence,
		// canonical flow and collector session still identify the same communication;
		// do not manufacture another sample from that metadata difference.
		if old.Kind != c.Kind || old.Scope != c.Scope || old.IOCType != c.IOCType || old.IOCValue != c.IOCValue || old.TCP == nil || old.TCP.FlowID != c.TCP.FlowID || old.TCP.Sequence != c.TCP.Sequence {
			continue
		}
		for _, saved := range input.HTTP.Records {
			if saved.SourceID == old.HitID && !saved.Truncated && saved.RawRequest == request.RawRequest && saved.SessionID != "" && saved.SessionID == request.SessionID {
				duplicate = true
				break
			}
		}
		if duplicate {
			break
		}
	}
	if !duplicate {
		manifest.PhaseOne.Contacts = append(manifest.PhaseOne.Contacts, c)
	}
	manifest.PhaseOne.Bindings = append(manifest.PhaseOne.Bindings, evidence.PhaseOneBinding{Scope: input.Scope, IOCType: ioc.Type, IOCValue: ioc.Value, SourceID: h.ID, Verified: true, Field: field})
}

func providerExchangeInWindow(x *providerHTTPExchange, input *evidence.Input) bool {
	return input.Window == nil || (!x.RequestTime.Before(input.Window.Start) && x.RequestTime.Before(input.Window.End))
}

// Repeated response/ACK hits can carry the same transaction's request context.
// They may enrich the structured source, but must not occupy additional
// semantic-operation budget ahead of the hit that actually captured the request.
func providerExchangeRequestOccurrence(m map[string]any, x *providerHTTPExchange) bool {
	p, err := snapshotDecodeFrame(m, asString(nestedMap(m, "raw_packet")["packet_hex"]))
	if err != nil || p.ErrorLayer() != nil {
		return false
	}
	tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || len(tcp.Payload) == 0 || tcp.Seq != x.requestSide.seq || !bytes.HasPrefix(x.requestSide.payload, tcp.Payload) {
		return false
	}
	return net.ParseIP(asString(m["src_ip"])).Equal(net.ParseIP(x.requestSide.src)) && net.ParseIP(asString(m["dst_ip"])).Equal(net.ParseIP(x.requestSide.dst))
}

// Keep diagnostics available to the caller without promoting an unverified
// response into the legacy fallback path for this transaction.
func providerExchangeProblem(x *providerHTTPExchange) string {
	if x != nil && x.Response == nil {
		return fmt.Sprintf("exchange_response_unavailable:%s", x.ResponseProblem)
	}
	return ""
}
