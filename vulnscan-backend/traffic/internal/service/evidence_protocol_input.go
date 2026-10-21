package service

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

const maxEvidenceMessageBytes = 1 << 20

func netIPv4(a [4]byte) string  { return netip.AddrFrom4(a).String() }
func netIPv6(a [16]byte) string { return netip.AddrFrom16(a).String() }

// Wire parsing is bounded and offline. Probe verdicts/verified flags are never
// promoted into authority. A captured packet is not a reassembled TCP stream.
func snapshotPayload(packet map[string]any) ([]byte, bool, string) {
	truncated, known := packet["capture_truncated"].(bool)
	if raw, ok := packet["payload_hex"].(string); ok {
		if len(raw) > 2*maxEvidenceMessageBytes {
			return nil, false, "message_budget_exceeded"
		}
		payload, err := decodeSnapshotPayloadHex(raw)
		if err != nil {
			return nil, false, "payload_hex_invalid"
		}
		if text := asString(packet["payload_text"]); text != "" && !bytes.Equal(payload, []byte(text)) {
			return payload, known && !truncated, "payload_representations_disagree"
		}
		return payload, known && !truncated, ""
	}
	text := asString(packet["payload_text"])
	if len(text) > maxEvidenceMessageBytes {
		return nil, false, "message_budget_exceeded"
	}
	// Printable text may be a transformed projection. Useful for headers, but
	// cannot establish complete bytes/body, even if the packet was not truncated.
	return []byte(text), false, "payload_bytes_unavailable"
}

func enrichSnapshotProtocols(input *evidence.Input, hit store.Hit, m map[string]any, manifest *SnapshotEvidenceManifest) {
	// Session-level app.http_url is a hint, never a captured request. Remove
	// this hit's projection before classifying its actual wire bytes.
	httpHint := false
	if input.HTTP != nil {
		kept := input.HTTP.Records[:0]
		for _, r := range input.HTTP.Records {
			if r.SourceID == hit.ID {
				httpHint = true
			} else {
				kept = append(kept, r)
			}
		}
		input.HTTP.Records = kept
	}
	unknownHTTP := func() {
		if input.HTTP == nil {
			input.HTTP = &evidence.HTTPData{}
		}
		input.HTTP.UnknownRequestIDs = append(input.HTTP.UnknownRequestIDs, hit.ID)
		manifest.addIssue(SnapshotInputIssue{Code: "http_request_classification_unknown", Stage: "parse_protocol", HitID: hit.ID, Scope: input.Scope})
	}
	packet := nestedMap(m, "raw_packet")
	if child := nestedMap(packet, "request"); len(child) > 0 && packet["report_quality_derivation"] == nil {
		packet = child
	}
	packet, frameProblem := snapshotFramePayload(packet, m, input)
	// Payload projections with a self-reported capture flag are not wire proof.
	// packet is the actual request child selected above when that format is used.
	requestWireVerified := frameProblem == "" && asString(packet["packet_hex"]) != ""
	payload, full, problem := snapshotPayload(packet)
	parseMap, parseHit := m, hit
	exchange := providerVerifiedHTTP(m)
	if exchange != nil && exchange.Request != nil && providerExchangeInWindow(exchange, input) {
		packet = exchange.Request
		payload, full, problem = snapshotPayload(packet)
		frameProblem = ""
		parseMap, parseHit.OccurredAt = exchange.RequestMap, exchange.RequestTime
		requestWireVerified = true // verified frames + reconstruction + HTTP framing
		// Keep the actual request parse accounted in the existing per-hit ledger.
		parseMap[snapshotParseContextKey] = m[snapshotParseContextKey]
	} else {
		exchange = nil
	}
	issue := func(code, field string) {
		manifest.addIssue(SnapshotInputIssue{Code: code, Stage: "parse_protocol", Field: field, HitID: hit.ID, Scope: input.Scope})
	}
	if frameProblem != "" {
		unknownHTTP()
		issue(frameProblem, "raw_packet.packet_hex")
		if input.Network != nil && len(input.Network.Connections) > 0 {
			c := &input.Network.Connections[len(input.Network.Connections)-1]
			c.PayloadBytes = nil
			c.ProtocolParsed = false
			c.AppProtocol = ""
			c.TCPState = ""
		}
		if input.HTTP != nil {
			kept := input.HTTP.Records[:0]
			for _, r := range input.HTTP.Records {
				if r.SourceID != hit.ID {
					kept = append(kept, r)
				}
			}
			input.HTTP.Records = kept
		}
		if input.DNS != nil {
			kept := input.DNS.Records[:0]
			for _, r := range input.DNS.Records {
				if r.SourceID != hit.ID {
					kept = append(kept, r)
				}
			}
			input.DNS.Records = kept
		}
		return
	}
	if problem != "" && (len(payload) > 0 || problem != "payload_bytes_unavailable") {
		issue(problem, "raw_packet.payload_hex/payload_text")
	}
	app := nestedMap(m, "app")
	if sni := strings.TrimSpace(asString(app["tls_sni"])); sni != "" {
		if input.TLS == nil {
			input.TLS = &evidence.TLSData{}
		}
		input.TLS.Records = append(input.TLS.Records, evidence.TLSRecord{SourceID: hit.ID, Time: hit.OccurredAt, SNI: sni})
		issue("tls_certificate_and_trust_unavailable", "app.tls_sni/certificate_chain")
	}
	if len(payload) == 0 {
		if !full {
			unknownHTTP()
		} else if input.HTTP != nil {
			input.HTTP.NonRequestPackets++
		}
		return
	}
	firstLine, _, _ := bytes.Cut(payload, []byte("\r\n"))
	_, _, httpLike := bytes.Cut(firstLine, []byte(" HTTP/1."))
	if httpLike {
		if input.HTTP == nil {
			input.HTTP = &evidence.HTTPData{}
		}
		input.HTTP.RequestCandidates++
		fieldsVerified := false
		record, protocolParsed, parseProblem := snapshotHTTPRequest(payload, full, parseHit, parseMap, app, &fieldsVerified)
		if parseProblem != "" {
			issue(parseProblem, "raw_packet.request")
		}
		if record.URL == "" && input.HTTP != nil {
			kept := input.HTTP.Records[:0]
			for _, r := range input.HTTP.Records {
				if r.SourceID != hit.ID {
					kept = append(kept, r)
				}
			}
			input.HTTP.Records = kept
		}
		if protocolParsed && input.Network != nil && len(input.Network.Connections) > 0 {
			last := &input.Network.Connections[len(input.Network.Connections)-1]
			last.AppProtocol, last.ProtocolParsed = "http", true
		}
		if record.URL != "" {
			if requestWireVerified && parseProblem == "" && protocolParsed && full && !record.Truncated && record.RequestID != "" && record.SessionID != "" {
				record.RequestVerification = &evidence.HTTPRequestVerification{Version: evidence.HTTPRequestVerificationVersion, Scope: input.Scope, SourceID: hit.ID, SourceOccurredAt: hit.OccurredAt, RequestID: record.RequestID, RequestTime: record.Time, URL: record.URL, Method: record.Method, SessionID: record.SessionID}
				if fieldsVerified {
					record.RequestVerification.FieldsVerified = true
					record.RequestVerification.FieldNames = evidence.HTTPRequestFieldNames(record.Fields)
				}
			}
			response := nestedMap(nestedMap(m, "raw_packet"), "response")
			if exchange != nil {
				response = exchange.Response
				if why := providerExchangeProblem(exchange); why != "" {
					issue(why, "exchange.response")
				}
			}
			if responseProblem := snapshotHTTPResponse(&record, packet, response, payload); responseProblem != "" {
				issue(responseProblem, "raw_packet.response")
			}
			if input.HTTP == nil {
				input.HTTP = &evidence.HTTPData{}
			}
			// Replace the sample-derived record from this same hit, never count twice.
			replaced := false
			for i := range input.HTTP.Records {
				if input.HTTP.Records[i].SourceID == hit.ID {
					input.HTTP.Records[i] = record
					replaced = true
					break
				}
			}
			if !replaced {
				input.HTTP.Records = append(input.HTTP.Records, record)
			}
		}
		return
	}
	// A complete response or another identified wire protocol cannot be a
	// request. Opaque bytes on an HTTP-hinted connection remain unresolved.
	knownNonRequest := bytes.HasPrefix(payload, []byte("HTTP/1.")) ||
		(len(payload) >= 3 && payload[0] >= 20 && payload[0] <= 23 && payload[1] == 3) ||
		strings.EqualFold(firstNonEmpty(asString(m["protocol"]), asString(m["proto"])), "udp")
	if (!full || httpHint) && !knownNonRequest {
		unknownHTTP()
	} else if input.HTTP != nil {
		input.HTTP.NonRequestPackets++
	}
	// Port alone never proves a protocol. Only attempt DNS when actual app
	// metadata identified DNS; successful binary decoding supplies the proof.
	if strings.TrimSpace(asString(app["dns_query"])) != "" || (len(payload) >= 12 && strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"]))) == "udp" && full) {
		data := payload
		proto := strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"])))
		if proto == "tcp" {
			if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
				issue("dns_tcp_message_incomplete", "raw_packet.payload_hex")
				return
			}
			data = data[2:]
		}
		msg, dnsErr := snapshotDecodeDNS(m, data)
		if dnsErr != nil || len(msg.Questions) != 1 || !full || msg.Truncated {
			if strings.TrimSpace(asString(app["dns_query"])) != "" {
				issue("dns_message_incomplete_or_invalid", "raw_packet.payload_hex")
			}
			return
		}
		domain := strings.TrimSuffix(msg.Questions[0].Name.String(), ".")
		if asString(app["dns_query"]) != "" && !strings.EqualFold(strings.TrimSuffix(asString(app["dns_query"]), "."), domain) {
			issue("dns_metadata_conflict", "app.dns_query")
			if input.DNS != nil {
				kept := input.DNS.Records[:0]
				for _, r := range input.DNS.Records {
					if r.SourceID != hit.ID {
						kept = append(kept, r)
					}
				}
				input.DNS.Records = kept
			}
			return
		}
		r := evidence.DNSRecord{SourceID: hit.ID, Time: hit.OccurredAt, Domain: domain, RCodeKnown: msg.Response, RCode: int(msg.RCode)}
		for _, answer := range msg.Answers {
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				r.Answers = append(r.Answers, netIPv4(body.A))
			case *dnsmessage.AAAAResource:
				r.Answers = append(r.Answers, netIPv6(body.AAAA))
			}
		}
		if input.DNS == nil {
			input.DNS = &evidence.DNSData{}
		}
		replaced := false
		for i := range input.DNS.Records {
			if input.DNS.Records[i].SourceID == hit.ID {
				input.DNS.Records[i] = r
				replaced = true
				break
			}
		}
		if !replaced {
			input.DNS.Records = append(input.DNS.Records, r)
		}
		if input.Network != nil && len(input.Network.Connections) > 0 {
			last := &input.Network.Connections[len(input.Network.Connections)-1]
			last.AppProtocol, last.ProtocolParsed = "dns", true
		}
	}
}

// Recover missing payload bytes from an actual Ethernet frame, checking the
// stored flow tuple. No live packet fetching or network access is performed.
func computeSnapshotFramePayload(packet, m map[string]any, input *evidence.Input) (map[string]any, string) {
	raw := asString(packet["packet_hex"])
	if raw == "" {
		return packet, ""
	}
	if len(raw) > 2*maxEvidenceMessageBytes {
		return packet, "message_budget_exceeded"
	}
	p, err := snapshotDecodeFrame(m, raw)
	if err != nil {
		return packet, "packet_hex_invalid"
	}
	if p.ErrorLayer() != nil {
		return packet, "packet_frame_invalid"
	}
	src, dst := "", ""
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		src, dst = ip.SrcIP.String(), ip.DstIP.String()
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			return packet, "packet_fragment_unreassembled"
		}
	}
	if l := p.Layer(layers.LayerTypeIPv6); l != nil {
		ip := l.(*layers.IPv6)
		src, dst = ip.SrcIP.String(), ip.DstIP.String()
		if p.Layer(layers.LayerTypeIPv6Fragment) != nil {
			return packet, "packet_fragment_unreassembled"
		}
	}
	if net.ParseIP(src) == nil || !net.ParseIP(src).Equal(net.ParseIP(asString(m["src_ip"]))) || !net.ParseIP(dst).Equal(net.ParseIP(asString(m["dst_ip"]))) {
		return packet, "packet_flow_tuple_conflict"
	}
	var body []byte
	var srcPort, dstPort uint16
	proto := ""
	rst := false
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		tcp := l.(*layers.TCP)
		body = tcp.Payload
		srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
		proto = "tcp"
		rst = tcp.RST
	}
	if l := p.Layer(layers.LayerTypeUDP); l != nil {
		udp := l.(*layers.UDP)
		body = udp.Payload
		srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
		proto = "udp"
	}
	sp, sok := strictUint(m["src_port"])
	dp, dok := strictUint(m["dst_port"])
	if !sok || !dok || uint64(srcPort) != sp || uint64(dstPort) != dp || proto != strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"]))) {
		return packet, "packet_flow_tuple_conflict"
	}
	if existing, ok := packet["payload_hex"].(string); ok {
		data, err := decodeSnapshotPayloadHex(existing)
		if err != nil || !bytes.Equal(data, body) {
			return packet, "packet_payload_conflict"
		}
		if rst && input.Network != nil && len(input.Network.Connections) > 0 {
			input.Network.Connections[len(input.Network.Connections)-1].TCPState = "RST"
		}
		return packet, ""
	}
	copy := map[string]any{}
	for k, v := range packet {
		copy[k] = v
	}
	copy["payload_hex"] = fmt.Sprintf("%x", body)
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		tcp := l.(*layers.TCP)
		copy["tcp_seq"] = uint64(tcp.Seq)
		copy["tcp_ack"] = uint64(tcp.Ack)
	}
	if rst && input.Network != nil && len(input.Network.Connections) > 0 {
		input.Network.Connections[len(input.Network.Connections)-1].TCPState = "RST"
	}
	return copy, ""
}

func snapshotHTTPResponse(record *evidence.HTTPRecord, request, response map[string]any, requestPayload []byte) string {
	if len(response) == 0 {
		return ""
	}
	if record.TransactionID == "" || record.SessionID == "" {
		return "http_pair_identity_missing"
	}
	seq, seqOK := strictUint(request["tcp_seq"])
	ack, ackOK := strictUint(response["tcp_ack"])
	reqAck, reqAckOK := strictUint(request["tcp_ack"])
	respSeq, respSeqOK := strictUint(response["tcp_seq"])
	if !seqOK || !ackOK || !reqAckOK || !respSeqOK || seq > 0xffffffff || ack > 0xffffffff || reqAck > 0xffffffff || respSeq > 0xffffffff || (seq+uint64(len(requestPayload)))&0xffffffff != ack || reqAck != respSeq {
		return "http_pair_sequence_unverified"
	}
	body, full, problem := snapshotPayload(response)
	if !full || problem != "" {
		return "http_response_incomplete"
	}
	reader := bufio.NewReader(bytes.NewReader(body))
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "http_response_invalid"
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxEvidenceMessageBytes+1))
	if err != nil || len(content) > maxEvidenceMessageBytes {
		return "http_response_incomplete"
	}
	if _, err := reader.Peek(1); err != io.EOF {
		return "http_response_multiple_messages_unsupported"
	}
	record.ResponseVerified = true
	record.ResponseStatus = resp.StatusCode
	record.ResponseLocation = resp.Header.Get("Location")
	record.ResponseURL = record.URL
	media, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if media == "text/html" {
		tokenizer := html.NewTokenizer(bytes.NewReader(content))
		actions := []string{}
		for {
			tt := tokenizer.Next()
			if tt == html.ErrorToken {
				if tokenizer.Err() != io.EOF {
					return "http_html_invalid"
				}
				break
			}
			if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
				t := tokenizer.Token()
				if t.Data == "form" {
					action := record.URL
					for _, a := range t.Attr {
						if a.Key == "action" && a.Val != "" {
							action = a.Val
						}
					}
					actions = append(actions, action)
				}
			}
		}
		if len(actions) == 1 {
			record.FormAction = actions[0]
		} else if len(actions) > 1 {
			return "http_multiple_forms_unsupported"
		}
	}
	// Location is observed, but following it is not proven; redirect chain
	// flags stay false until a verified transaction join is available.
	return ""
}

func snapshotHTTPRequest(payload []byte, full bool, hit store.Hit, m, app map[string]any, fieldsVerified *bool) (evidence.HTTPRecord, bool, string) {
	*fieldsVerified = false
	if c := snapshotParsing(m); c != nil {
		c.httpParses++
	}
	r := evidence.HTTPRecord{SourceID: hit.ID, Time: hit.OccurredAt, TransactionID: asString(m["transaction_id"]), SessionID: asString(m["session_id"]), Truncated: true}
	reader := bufio.NewReader(bytes.NewReader(payload))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return r, false, "http_request_invalid"
	}
	defer req.Body.Close()
	r.Method, r.UserAgent = req.Method, req.UserAgent()
	if (asString(app["http_method"]) != "" && asString(app["http_method"]) != req.Method) || (asString(app["http_host"]) != "" && !strings.EqualFold(asString(app["http_host"]), req.Host)) {
		return r, true, "http_metadata_conflict"
	}
	u := *req.URL
	if !u.IsAbs() {
		u.Scheme, u.Host = "http", req.Host
	}
	if u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return r, true, "http_authority_missing"
	}
	if raw := asString(app["http_url"]); raw != "" && raw != req.RequestURI && raw != u.String() {
		return r, true, "http_metadata_conflict"
	}
	r.URL = u.String()
	body, err := io.ReadAll(io.LimitReader(req.Body, maxEvidenceMessageBytes+1))
	if err != nil || len(body) > maxEvidenceMessageBytes {
		return r, true, "http_body_incomplete_or_oversized"
	}
	if !full {
		return r, true, "http_body_completeness_unverified"
	}
	if req.ContentLength >= 0 && int64(len(body)) != req.ContentLength {
		return r, true, "http_content_length_mismatch"
	}
	// Multiple messages in one packet need stream/message indexing; until then
	// the first request is only a partial observation, not a complete denominator.
	if _, err := reader.Peek(1); err != io.EOF {
		return r, true, "http_multiple_messages_unsupported"
	}
	r.Truncated = false
	r.RawRequest = string(payload)
	r.ParsedBody = string(body)
	r.RequestID = snapshotHTTPRequestID(m, payload)
	size := uint64(len(body))
	r.BodyLength = &size
	r.Fields = map[string]string{}
	r.FieldValuesRedacted = true
	fieldValues := map[string]string{}
	multiValue := false
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		r.Truncated = true
		return r, true, "http_query_invalid"
	}
	for key, values := range query {
		r.Fields[key] = "[redacted]"
		if len(values) != 1 {
			multiValue = true
		} else {
			fieldValues[key] = values[0]
		}
	}
	media, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil && len(body) > 0 {
		r.Truncated = true
		return r, true, "http_body_format_unknown"
	}
	switch media {
	case "application/x-www-form-urlencoded":
		fields, err := url.ParseQuery(string(body))
		if err != nil {
			r.Truncated = true
			return r, true, "http_form_invalid"
		}
		for key, values := range fields {
			r.Fields[key] = "[redacted]"
			if _, exists := fieldValues[key]; exists {
				multiValue = true
			}
			if len(values) != 1 {
				multiValue = true
			} else {
				fieldValues[key] = values[0]
			}
		}
	case "application/json":
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
			if len(body) > 0 {
				r.Truncated = true
				return r, true, "http_json_object_unavailable"
			}
		} else {
			// Unmarshal silently keeps the last duplicate key. Refuse that
			// ambiguity instead of producing a false complete field inventory.
			decoder := json.NewDecoder(bytes.NewReader(body))
			_, _ = decoder.Token()
			seen := map[string]bool{}
			for decoder.More() {
				token, _ := decoder.Token()
				key, ok := token.(string)
				if !ok || seen[key] {
					r.Truncated = true
					return r, true, "http_json_duplicate_field"
				}
				seen[key] = true
				var value json.RawMessage
				if decoder.Decode(&value) != nil {
					r.Truncated = true
					return r, true, "http_json_object_unavailable"
				}
			}
			for key, value := range fields {
				r.Fields[key] = "[redacted]"
				if _, exists := fieldValues[key]; exists {
					multiValue = true
				}
				if bytes.HasPrefix(bytes.TrimSpace(value), []byte("{")) || bytes.HasPrefix(bytes.TrimSpace(value), []byte("[")) {
					r.Truncated = true
					return r, true, "http_nested_fields_unsupported"
				}
				var text string
				if json.Unmarshal(value, &text) == nil {
					fieldValues[key] = text
				} else {
					fieldValues[key] = string(value)
				}
			}
		}
	case "", "text/plain":
	default:
		// Bytes and length are known, but credential field extraction is incomplete.
		if len(body) > 0 {
			r.Truncated = true
			return r, true, "http_body_format_unsupported"
		}
	}
	if multiValue {
		return r, true, "http_multivalue_encoding_unsupported"
	}
	summary := evidence.SummarizeHTTPFieldEncoding(fieldValues)
	r.EncodingSummary = &summary
	// Opaque text is a valid request body, but not a verified field inventory.
	*fieldsVerified = len(body) == 0 || media == "application/x-www-form-urlencoded" || media == "application/json"
	return r, true, ""
}

// Stable across revisions/snapshots and independent of probe transaction labels.
func snapshotHTTPRequestID(m map[string]any, payload []byte) string {
	packet := nestedMap(m, "raw_packet")
	if child := nestedMap(packet, "request"); len(child) > 0 && packet["report_quality_derivation"] == nil {
		packet = child
	}
	seq := packet["tcp_seq"]
	if p, err := snapshotDecodeFrame(m, asString(packet["packet_hex"])); err == nil {
		if l := p.Layer(layers.LayerTypeTCP); l != nil {
			seq = uint64(l.(*layers.TCP).Seq)
		}
	}
	return digest([]any{m["device_id"], m["src_ip"], m["dst_ip"], m["src_port"], m["dst_port"], seq, string(payload)})
}
