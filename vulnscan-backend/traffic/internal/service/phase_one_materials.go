package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type PhaseOneSnapshotSource struct {
	EventID           string `json:"event_id"`
	Version           int64  `json:"version"`
	Watermark         int64  `json:"watermark"`
	RevisionWatermark int64  `json:"revision_watermark"`
	LoadedHits        int64  `json:"loaded_hits"`
	Complete          bool   `json:"complete"`
}
type PhaseOneContact struct {
	ID       string                 `json:"id"`
	Kind     string                 `json:"kind"`
	HitID    string                 `json:"hit_id"`
	Time     time.Time              `json:"time"`
	Scope    evidence.Scope         `json:"scope"`
	IOCType  string                 `json:"ioc_type"`
	IOCValue string                 `json:"ioc_value"`
	Snapshot PhaseOneSnapshotSource `json:"snapshot"`
	TCP      *PhaseOneTCPContact    `json:"tcp,omitempty"`
}

// Flow identity and sequence come from a validated frame. SessionStart is
// retained only when the collector's flow timestamp is valid for that frame.
type PhaseOneTCPContact struct {
	FlowID       string     `json:"flow_id"`
	Sequence     uint32     `json:"sequence"`
	SessionStart *time.Time `json:"session_start,omitempty"`
}
type PhaseOneMaterials struct {
	CurrentBindings        []evidence.PhaseOneBinding      `json:"current_bindings,omitempty"`
	TemporalWindowCoverage *PhaseOneTemporalWindowCoverage `json:"temporal_window_coverage,omitempty"`
	CurrentContacts        []PhaseOneContact               `json:"current_contacts,omitempty"`
	CurrentComplete        bool                            `json:"current_complete"`
	CurrentIncomplete      map[string][]string             `json:"current_scope_incomplete,omitempty"`
	Expanded               bool                            `json:"expanded"`
	Records                []PhaseOneRecord                `json:"records"`
	Bindings               []evidence.PhaseOneBinding      `json:"bindings"`
	Contacts               []PhaseOneContact               `json:"contacts"`
	Sources                []PhaseOneSnapshotSource        `json:"sources"`
	Diagnostics            []string                        `json:"diagnostics"`
	Complete               bool                            `json:"complete"`
	ScopeIncomplete        map[string][]string             `json:"scope_incomplete,omitempty"`
	RawHits                int64                           `json:"raw_hits"`
	DuplicateContacts      int                             `json:"duplicate_contacts"`
}

// This policy applies only to the current-event jitter contact timeline. It is
// separate from verified capture, transaction and protocol-family completeness.
type PhaseOneTemporalWindowCoverage struct {
	Basis           string `json:"basis"`
	CurrentComplete bool   `json:"current_complete"`
	Complete        bool   `json:"complete"`
}

const assumedTemporalWindowCoverage = "default_assumption"

type PhaseOneRecord struct {
	RawRequest    string               `json:"raw_request,omitempty"`
	ParsedBody    string               `json:"parsed_body,omitempty"`
	Hit           evidence.Hit         `json:"hit"`
	IOCType       string               `json:"ioc_type"`
	IOCValue      string               `json:"ioc_value"`
	HTTP          *evidence.HTTPRecord `json:"http,omitempty"`
	DNS           *evidence.DNSRecord  `json:"dns,omitempty"`
	HTTPCandidate bool                 `json:"http_candidate"`
}

func phaseOneSnapshotSource(s EvidenceSnapshot) PhaseOneSnapshotSource {
	return PhaseOneSnapshotSource{EventID: s.EventID, Version: s.Version, Watermark: s.Watermark, RevisionWatermark: s.RevisionWatermark}
}

// Reads actual frames, not IOC descriptions or app strings. Scope has already
// been resolved against the server asset registry. No reputation gate here.
func collectPhaseOneMaterials(manifest *SnapshotEvidenceManifest, h store.Hit, m map[string]any, input evidence.Input, assets []domain.Asset, snap EvidenceSnapshot) {
	if manifest.PhaseOne == nil {
		manifest.PhaseOne = &PhaseOneMaterials{Bindings: []evidence.PhaseOneBinding{}, Contacts: []PhaseOneContact{}, Sources: []PhaseOneSnapshotSource{phaseOneSnapshotSource(snap)}, Complete: true, Diagnostics: []string{}}
	}
	out := manifest.PhaseOne
	out.RawHits++
	b := evidence.PhaseOneBinding{Scope: input.Scope, IOCType: strings.ToLower(asString(m["ioc_type"])), IOCValue: asString(m["ioc_value"]), SourceID: h.ID}
	reject := func(reason string) {
		b.Reason = reason
		out.Bindings = append(out.Bindings, b)
		out.Diagnostics = append(out.Diagnostics, h.ID+":"+reason)
		if reason != "ioc_type_value_not_at_wire_field" {
			markPhaseOneScopeIncomplete(out, b.Scope, b.IOCType, b.IOCValue, reason)
		}
	}
	packet := nestedMap(m, "raw_packet")
	raw, err := hex.DecodeString(asString(packet["packet_hex"]))
	if err != nil || len(raw) == 0 {
		reject("ioc_wire_frame_missing")
		return
	}
	checked, problem := snapshotFramePayload(packet, m, &input)
	if problem != "" {
		reject(problem)
		return
	}
	payload, full, why := snapshotPayload(checked)
	if why != "" {
		reject(why)
		return
	}
	if !full {
		reject("capture_completeness_unverified")
		return
	}
	t, err := time.Parse(time.RFC3339Nano, asString(packet["capture_time"]))
	if err != nil || !t.Equal(h.OccurredAt) {
		reject("capture_time_binding_invalid")
		return
	}
	var p gopacket.Packet
	if c := snapshotParsing(m); c != nil {
		p = c.decoded
	}
	if p == nil {
		p = gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	}
	if p.ErrorLayer() != nil {
		reject("wire_decode_failed")
		return
	}
	tcp, _ := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	udp, _ := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
	src, dst := asString(m["src_ip"]), asString(m["dst_ip"])
	if b.IOCType == "ip" {
		iocAsset, registered := registeredSnapshotAsset(assets, b.IOCValue)
		localIOC := registered && iocAsset == input.Scope.AssetID
		if !localIOC && b.IOCValue == src {
			b.Field = "ipv4_or_ipv6.src_ip"
		} else if !localIOC && b.IOCValue == dst {
			b.Field = "ipv4_or_ipv6.dst_ip"
		}
	}
	dns := dnsmessage.Message{}
	dnsOK := false
	dnsBytes := payload
	if tcp != nil && len(dnsBytes) > 2 && int(binary.BigEndian.Uint16(dnsBytes[:2])) == len(dnsBytes)-2 {
		dnsBytes = dnsBytes[2:]
	}
	if udp != nil && (udp.SrcPort == 53 || udp.DstPort == 53) || tcp != nil && (tcp.SrcPort == 53 || tcp.DstPort == 53) {
		var dnsErr error
		dns, dnsErr = snapshotDecodeDNS(m, dnsBytes)
		dnsOK = dnsErr == nil && !dns.Truncated && len(dns.Questions) == 1
	}
	var request *evidence.HTTPRecord
	if input.HTTP != nil {
		for i := range input.HTTP.Records {
			r := &input.HTTP.Records[i]
			if r.SourceID == h.ID && !r.Truncated && r.RawRequest != "" {
				request = r
			}
		}
	}
	record := PhaseOneRecord{Hit: evidence.Hit{ID: h.ID, OccurredAt: t, Scope: input.Scope}, IOCType: b.IOCType, IOCValue: b.IOCValue}
	if input.HTTP != nil {
		for _, id := range input.HTTP.UnknownRequestIDs {
			if id == h.ID {
				record.HTTPCandidate = true
			}
		}
	}
	firstLine, _, _ := bytes.Cut(payload, []byte("\r\n"))
	if bytes.Contains(firstLine, []byte(" HTTP/1.")) {
		record.HTTPCandidate = true
	}
	for _, r := range func() []evidence.HTTPRecord {
		if input.HTTP != nil {
			return input.HTTP.Records
		}
		return nil
	}() {
		if r.SourceID == h.ID {
			record.HTTPCandidate = true
			copy := r
			record.HTTP = &copy
			record.RawRequest, record.ParsedBody = r.RawRequest, r.ParsedBody
		}
	}
	if dnsOK {
		record.DNS = &evidence.DNSRecord{SourceID: h.ID, Time: t, Domain: strings.TrimSuffix(dns.Questions[0].Name.String(), "."), RCode: int(dns.RCode), RCodeKnown: true}
	}
	out.Records = append(out.Records, record)
	if b.IOCType == "domain" {
		equal := func(s string) bool {
			return strings.EqualFold(strings.TrimSuffix(s, "."), strings.TrimSuffix(b.IOCValue, "."))
		}
		if request != nil {
			u, _ := url.Parse(request.URL)
			if u != nil && equal(u.Hostname()) {
				b.Field = "http.request.host"
			}
		}
		if dnsOK && providerObservedDomainMatchesIOC(dns.Questions[0].Name.String(), b.IOCValue) {
			b.Field = "dns.question.name"
		}
		if sni := phaseOneSNI(payload); sni != "" && equal(sni) {
			b.Field = "tls.client_hello.server_name"
		}
	}
	if b.IOCType == "url" && request != nil && request.URL == b.IOCValue {
		b.Field = "http.request.url"
	}
	if b.Field == "" {
		reject("ioc_type_value_not_at_wire_field")
		return
	}
	b.Verified = true
	out.Bindings = append(out.Bindings, b)
	outbound := false
	if id, ok := registeredSnapshotAsset(assets, src); ok && id == input.Scope.AssetID {
		outbound = true
	}
	key, kind := "", ""
	tuple := []any{m["device_id"], src, dst, m["src_port"], m["dst_port"]}
	if tcp != nil && outbound && tcp.SYN && !tcp.ACK {
		key = digest(append(tuple, "syn", tcp.Seq))
		kind = "tcp_initiation"
	}
	if tcp != nil && request != nil {
		key = digest(append(tuple, "request", tcp.Seq, request.RawRequest))
		kind = "complete_http_request"
	}
	if udp != nil && dnsOK && !dns.Response {
		key = digest(append(tuple, "dns_question", dns.ID, string(dnsBytes)))
		kind = "dns_question"
	}
	if key != "" {
		contact := PhaseOneContact{ID: key, Kind: kind, HitID: h.ID, Time: t, Scope: input.Scope, IOCType: b.IOCType, IOCValue: b.IOCValue, Snapshot: phaseOneSnapshotSource(snap)}
		if tcp != nil {
			contact.TCP = &PhaseOneTCPContact{FlowID: digest([]any{input.Scope.DeviceID, src, dst, uint16(tcp.SrcPort), uint16(tcp.DstPort)}), Sequence: tcp.Seq}
			if start, err := time.Parse(time.RFC3339Nano, asString(packet["session_start_time"])); err == nil && !start.IsZero() && !start.After(t) {
				start = start.UTC()
				contact.TCP.SessionStart = &start
				// A reused wire tuple/sequence in a later collector session is
				// a distinct contact; retransmissions within a session are not.
				contact.ID = digest([]any{contact.ID, start})
			}
		}
		out.Contacts = append(out.Contacts, contact)
	}
}

// Parse a complete TLS ClientHello extension list. Never synthesize HTTP/DNS.
func phaseOneSNI(b []byte) string {
	if len(b) < 9 || b[0] != 22 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if n > len(b)-5 || b[5] != 1 {
		return ""
	}
	b = b[5 : 5+n]
	if len(b) < 39 {
		return ""
	}
	n = int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n != len(b)-4 {
		return ""
	}
	i := 38
	i += 1 + int(b[i])
	if i+2 > len(b) {
		return ""
	}
	n = int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2 + n
	if i >= len(b) {
		return ""
	}
	i += 1 + int(b[i])
	if i+2 > len(b) {
		return ""
	}
	n = int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if i+n != len(b) {
		return ""
	}
	for i+4 <= len(b) {
		typ, l := binary.BigEndian.Uint16(b[i:i+2]), int(binary.BigEndian.Uint16(b[i+2:i+4]))
		i += 4
		if i+l > len(b) {
			return ""
		}
		v := b[i : i+l]
		i += l
		if typ == 0 && len(v) >= 5 && int(binary.BigEndian.Uint16(v[:2])) == len(v)-2 && v[2] == 0 {
			size := int(binary.BigEndian.Uint16(v[3:5]))
			if size == len(v)-5 {
				return string(v[5:])
			}
		}
	}
	return ""
}

// The manifest is independent of the current snapshot. Each source freezes its
// own watermarks. Packets/ACKs and repeated revisions never become contacts.
func (s Services) phaseOneTimeline(ctx context.Context, snap EvidenceSnapshot, current PhaseOneMaterials, h ReportHistory, assets []domain.Asset) (PhaseOneMaterials, error) {
	current = dedupPhaseOneContacts(current)
	out := current
	out.CurrentContacts = append([]PhaseOneContact(nil), current.Contacts...)
	out.CurrentComplete = current.Complete
	out.CurrentIncomplete = clonePhaseOneIncomplete(current.ScopeIncomplete)
	out.ScopeIncomplete = clonePhaseOneIncomplete(current.ScopeIncomplete)
	out.Bindings = append([]evidence.PhaseOneBinding(nil), current.Bindings...)
	out.Contacts = append([]PhaseOneContact(nil), current.Contacts...)
	out.Sources = append([]PhaseOneSnapshotSource(nil), current.Sources...)
	out.Diagnostics = append([]string(nil), current.Diagnostics...)
	out = dedupPhaseOneContacts(out)
	enough := func() bool {
		counts := map[string]int{}
		days := map[string]map[string]bool{}
		loc := time.FixedZone("Asia/Shanghai", 8*3600)
		for _, c := range out.Contacts {
			k := scopeKey(c.Scope) + c.IOCType + ":" + c.IOCValue
			counts[k]++
			if days[k] == nil {
				days[k] = map[string]bool{}
			}
			days[k][c.Time.In(loc).Format("2006-01-02")] = true
		}
		if len(counts) == 0 {
			return false
		}
		for k, n := range counts {
			if n < 16 || len(days[k]) < 3 {
				return false
			}
		}
		for _, binding := range current.Bindings {
			if binding.Verified {
				key := scopeKey(binding.Scope) + binding.IOCType + ":" + binding.IOCValue
				if counts[key] < 16 || len(days[key]) < 3 {
					return false
				}
			}
		}
		return true
	}
	if enough() {
		return dedupPhaseOneContacts(out), nil
	}
	out.Complete = out.Complete && !h.Truncated && h.ExcludedCount == 0 && h.Status == "available"
	limits := contextPipelineLimits(ctx)
	maxSnapshots, maxHits, maxBytes := limits.HistorySnapshots, limits.HistoryHits, limits.HistoryBytes
	featureBytes := int64(0)
	loaded, rawBytes := int64(0), int64(0)
	for index, row := range h.Rows {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if index >= maxSnapshots {
			out.Complete = false
			out.Diagnostics = append(out.Diagnostics, "timeline_snapshot_budget_exceeded")
			break
		}
		var hs EvidenceSnapshot
		var err error
		if h.FrozenSnapshots != nil {
			var ok bool
			hs, ok = h.FrozenSnapshots[row.EventID]
			if !ok {
				err = fmt.Errorf("historical_snapshot_not_frozen")
			}
		} else {
			hs, err = s.EvidenceSnapshot(ctx, row.EventID, 0)
		}
		if err != nil {
			out.Complete = false
			out.Diagnostics = append(out.Diagnostics, row.EventID+":historical_snapshot_unavailable")
			continue
		}
		source := phaseOneSnapshotSource(hs)
		if hs.Count > maxHits-loaded {
			out.Complete = false
			out.Diagnostics = append(out.Diagnostics, "timeline_hit_budget_exceeded")
			break
		}
		q := store.HitQuery{Sources: hs.Sources, Watermark: hs.Watermark, Limit: 250}
		seenHits := map[string]bool{}
		for {
			page, readErr := snapshotBoundedPage(ctx, s.Store, q, hs.RevisionWatermark)
			if m := pipelineMetrics(ctx); m != nil {
				m.HistoricalReadPages++
			}
			if readErr != nil {
				return out, readErr
			}
			if len(page) == 0 {
				source.Complete = source.LoadedHits == hs.Count
				break
			}
			for _, hit := range page {
				if m := pipelineMetrics(ctx); m != nil {
					m.HistoricalReadBytes += int64(len(hit.Raw))
				}
				loaded++
				source.LoadedHits++
				rawBytes += int64(len(hit.Raw))
				if rawBytes > maxBytes {
					out.Complete = false
					out.Diagnostics = append(out.Diagnostics, "timeline_byte_budget_exceeded")
					out.Sources = append(out.Sources, source)
					return dedupPhaseOneContacts(out), nil
				}
				if seenHits[hit.ID] {
					source.Complete = false
					out.Complete = false
					continue
				}
				seenHits[hit.ID] = true
				if hit.OccurredAt.Before(h.Start) || !hit.OccurredAt.Before(h.End) {
					continue
				}
				m := map[string]any{}
				decoder := json.NewDecoder(bytes.NewReader(hit.Raw))
				decoder.UseNumber()
				if decodeErr := decoder.Decode(&m); decodeErr != nil {
					out.Complete = false
					continue
				}
				parsed := &snapshotParseContext{}
				m[snapshotParseContextKey] = parsed
				scope, remote, port, ok := snapshotScope(m, assets)
				if !ok {
					if !phaseOneUnrelatedFrame(m, assets) {
						out.Complete = false
					} else {
						out.Diagnostics = append(out.Diagnostics, hit.ID+":verified_frame_outside_eligible_scopes")
					}
					continue
				}
				allowed := false
				for _, b := range current.Bindings {
					if b.Verified && b.Scope == scope && b.IOCType == asString(m["ioc_type"]) && b.IOCValue == asString(m["ioc_value"]) {
						allowed = true
						break
					}
				}
				if !allowed {
					continue
				}
				reportVerifyDatagram(m)
				input := evidence.Input{Scope: scope}
				adaptSnapshotProtocols(&input, hit, m, remote, port, true)
				temp := SnapshotEvidenceManifest{}
				enrichSnapshotProtocols(&input, hit, m, &temp)
				collectPhaseOneMaterials(&temp, hit, m, input, assets, hs)
				if metrics := pipelineMetrics(ctx); metrics != nil {
					metrics.JSONDecodes++
					metrics.WireFrameDecodes += parsed.frameDecodes
					metrics.HTTPRequestParses += parsed.httpParses
					metrics.DNSMessageParses += parsed.dnsParses
				}
				if temp.PhaseOne != nil {
					featureBytes += snapshotFeatureCharge(temp.PhaseOne.Contacts, temp.PhaseOne.Diagnostics)
					if featureBytes > limits.FeatureBytes {
						out.Complete = false
						out.Diagnostics = append(out.Diagnostics, "timeline_feature_budget_exceeded")
						out.Sources = append(out.Sources, source)
						return dedupPhaseOneContacts(out), nil
					}
					for key, reasons := range temp.PhaseOne.ScopeIncomplete {
						if out.ScopeIncomplete == nil {
							out.ScopeIncomplete = map[string][]string{}
						}
						out.ScopeIncomplete[key] = append(out.ScopeIncomplete[key], reasons...)
					}
					out.Contacts = append(out.Contacts, temp.PhaseOne.Contacts...)
					out.Diagnostics = append(out.Diagnostics, temp.PhaseOne.Diagnostics...)
				}
			}
			tail := page[len(page)-1]
			if !q.AfterTime.IsZero() && (tail.OccurredAt.Before(q.AfterTime) || tail.OccurredAt.Equal(q.AfterTime) && tail.ID <= q.AfterID) {
				return out, fmt.Errorf("timeline_cursor_stalled")
			}
			q.AfterTime, q.AfterID = tail.OccurredAt, tail.ID
		}
		if !source.Complete {
			out.Complete = false
		}
		out.Sources = append(out.Sources, source)
	}
	return dedupPhaseOneContacts(out), nil
}
func dedupPhaseOneContacts(m PhaseOneMaterials) PhaseOneMaterials {
	// Superseding a SYN is deduplication, not evidence of missing capture. Clear
	// only that obsolete reason; retain truncation, parsing and binding failures.
	m.ScopeIncomplete = phaseOneContactIncomplete(m.ScopeIncomplete)
	m.CurrentIncomplete = phaseOneContactIncomplete(m.CurrentIncomplete)
	sort.Slice(m.Contacts, func(i, j int) bool {
		a, b := m.Contacts[i], m.Contacts[j]
		if a.Time.Equal(b.Time) {
			return a.HitID < b.HitID
		}
		return a.Time.Before(b.Time)
	})
	requests := map[string][]PhaseOneContact{}
	for _, c := range m.Contacts {
		if c.Kind == "complete_http_request" && c.TCP != nil {
			if key := phaseOneTCPContactKey(c, c.TCP.Sequence-1); key != "" {
				requests[key] = append(requests[key], c)
			}
		}
	}
	seen := map[string]bool{}
	kept := []PhaseOneContact{}
	for _, c := range m.Contacts {
		k := scopeKey(c.Scope) + ":" + c.IOCType + ":" + c.IOCValue + ":" + c.ID
		if seen[k] {
			m.DuplicateContacts++
			continue
		}
		seen[k] = true
		// A first HTTP request consumes the sequence immediately after its SYN.
		// Require the same wire flow, collector session start, scope and IOC.
		// Unpaired SYNs remain a separate population and never count as HTTP.
		if c.Kind == "tcp_initiation" && c.TCP != nil {
			superseded := false
			for _, request := range requests[phaseOneTCPContactKey(c, c.TCP.Sequence)] {
				if !request.Time.Before(c.Time) {
					m.Diagnostics = append(m.Diagnostics, c.HitID+":tcp_syn_superseded_by_http_request:"+request.HitID)
					superseded = true
					break
				}
			}
			if superseded {
				continue
			}
		}
		kept = append(kept, c)
	}
	m.Contacts = kept
	return m
}

func phaseOneTCPContactKey(c PhaseOneContact, synSequence uint32) string {
	if c.TCP == nil || c.TCP.FlowID == "" || c.TCP.SessionStart == nil || c.TCP.SessionStart.IsZero() || c.TCP.SessionStart.After(c.Time) {
		return ""
	}
	return digest([]any{c.Scope, c.IOCType, c.IOCValue, c.TCP.FlowID, c.TCP.SessionStart.UTC(), synSequence})
}

func phaseOneContactIncomplete(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for key, reasons := range in {
		for _, reason := range reasons {
			if reason != "syn_excluded_from_http_request_timeline" {
				out[key] = append(out[key], reason)
			}
		}
	}
	return out
}

func markPhaseOneScopeIncomplete(m *PhaseOneMaterials, s evidence.Scope, typ, value, reason string) {
	if m.ScopeIncomplete == nil {
		m.ScopeIncomplete = map[string][]string{}
	}
	k := scopeKey(s) + typ + ":" + value
	m.ScopeIncomplete[k] = append(m.ScopeIncomplete[k], reason)
}

func clonePhaseOneIncomplete(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Exclude only a complete, wire-verified tuple that cannot belong to any
// registered eligible endpoint. Unknown/missing frames remain coverage gaps.
func phaseOneUnrelatedFrame(m map[string]any, assets []domain.Asset) bool {
	if asString(nestedMap(m, "raw_packet")["packet_hex"]) == "" {
		return false
	}
	reportVerifyDatagram(m)
	packet := nestedMap(m, "raw_packet")
	if truncated, known := packet["capture_truncated"].(bool); !known || truncated {
		return false
	}
	// ICMP has no application transaction or TCP/UDP endpoint. Verify its
	// actual IP header and complete datagram before excluding it, rather than
	// trusting the saved protocol name or zero-port metadata.
	if strings.EqualFold(asString(m["protocol"]), "icmp") && packet["report_quality_derivation"] != nil {
		raw, err := hex.DecodeString(asString(packet["packet_hex"]))
		if err != nil {
			return false
		}
		frame := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
		if layer := frame.Layer(layers.LayerTypeIPv4); layer != nil && frame.ErrorLayer() == nil && frame.Layer(layers.LayerTypeICMPv4) != nil {
			ip := layer.(*layers.IPv4)
			return ip.SrcIP.Equal(net.ParseIP(asString(m["src_ip"]))) && ip.DstIP.Equal(net.ParseIP(asString(m["dst_ip"])))
		}
	}
	if _, problem := snapshotFramePayload(packet, m, &evidence.Input{}); problem != "" {
		return false
	}
	_, src := registeredSnapshotAsset(assets, asString(m["src_ip"]))
	_, dst := registeredSnapshotAsset(assets, asString(m["dst_ip"]))
	if !src && !dst {
		return true
	}
	sp, sok := strictUint(m["src_port"])
	dp, dok := strictUint(m["dst_port"])
	// Zero-port tuples are outside snapshotScope's supported endpoint domain;
	// they cannot alias any accepted positive-port scope.
	return sok && dok && (sp == 0 || dp == 0)
}
