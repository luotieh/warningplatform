package service

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// A single lifetime is one already bounded collection/assembly. It holds only
// summary scalars and source IDs; it has no Reader and never retains raw frames.
type providerSessionAccumulator struct {
	assets     []domain.Asset
	groups     map[string]*providerSessionGroup
	identities map[string]*providerSessionGroup
	issues     []SnapshotInputIssue
	issueCount int
}

type providerSessionGroup struct {
	scope     evidence.Scope
	id, tuple string
	first     uint64
	rows      []providerSessionRow
	clients   map[string]bool
	local     string
	problem   string
}

type providerSessionRow struct {
	id     string
	last   uint64
	counts [5]uint64 // client/server packets, client/server wire bytes, hit count
}

func newProviderSessionAccumulator(assets []domain.Asset) *providerSessionAccumulator {
	return &providerSessionAccumulator{assets: assets, groups: map[string]*providerSessionGroup{}, identities: map[string]*providerSessionGroup{}}
}

func (a *providerSessionAccumulator) issue(hid string, scope evidence.Scope, code string) {
	a.issueCount++
	// Reuse the manifest's bounded final ledger, and bound our staging as well.
	if len(a.issues) < 64 {
		a.issues = append(a.issues, SnapshotInputIssue{Code: code, Stage: "session_summary", Field: "session_summary", HitID: hid, Scope: scope})
	}
}

// observe consumes the existing JSON decode and parse cache. The caller must
// call it before copying that cache's parse counters into the manifest.
func (a *providerSessionAccumulator) observe(h store.Hit, m map[string]any, input evidence.Input) {
	summary := nestedMap(m, "session_summary")
	if len(summary) == 0 {
		return
	}
	sid := strings.TrimSpace(asString(m["session_id"]))
	scope, _, _, ok := snapshotScope(m, a.assets)
	if !ok || scope != input.Scope || sid == "" || h.ID == "" || h.OccurredAt.IsZero() || input.Window == nil {
		a.issue(h.ID, input.Scope, "session_summary_binding_invalid")
		return
	}
	key := scopeKey(scope) + "\x00" + sid
	g := a.groups[key]
	if g == nil {
		g = &providerSessionGroup{scope: scope, id: sid, clients: map[string]bool{}}
		a.groups[key] = g
	}
	reject := func(code string) { g.problem = code; a.issue(h.ID, scope, code) }
	first, firstOK := strictUint(summary["first_time_usec"])
	last, lastOK := strictUint(summary["last_time_usec"])
	// UTC JSON timestamps must remain representable (year <= 9999), without
	// overflowing microseconds into nanoseconds during conversion.
	const maxUnixMicro = uint64(253402300799999999)
	if !firstOK || !lastOK || first == 0 || first > last || last > maxUnixMicro {
		reject("session_summary_time_invalid")
		return
	}
	start, end := time.UnixMicro(int64(first)).UTC(), time.UnixMicro(int64(last)).UTC()
	if !input.Window.Start.Before(input.Window.End) || h.OccurredAt.Before(input.Window.Start) || !h.OccurredAt.Before(input.Window.End) || h.OccurredAt.Before(start) || h.OccurredAt.After(end) {
		reject("session_summary_window_binding_invalid")
		return
	}
	// A later revision keeps the original occurrence but can describe more
	// observed packets. Retain its own reported span without extending the
	// event/timeline window or authorizing complete-session computations.
	if start.Before(input.Window.Start) || !end.Before(input.Window.End) {
		a.issue(h.ID, scope, "session_summary_observation_span_outside_event_window")
	}
	endpoints := []string{}
	local := ""
	for _, side := range []string{"src", "dst"} {
		address, err := netip.ParseAddr(asString(m[side+"_ip"]))
		port, valid := strictUint(m[side+"_port"])
		if err != nil || !valid || port == 0 || port > 65535 {
			reject("session_summary_tuple_invalid")
			return
		}
		endpoint := net.JoinHostPort(address.Unmap().String(), strconv.FormatUint(port, 10))
		endpoints = append(endpoints, endpoint)
		if asset, registered := registeredSnapshotAsset(a.assets, address.Unmap().String()); registered && asset == scope.AssetID {
			local = endpoint
		}
	}
	sort.Strings(endpoints)
	tuple := strings.ToLower(firstNonEmpty(asString(m["protocol"]), asString(m["proto"]))) + ":" + endpoints[0] + "|" + endpoints[1]
	if g.tuple != "" && (g.tuple != tuple || g.first != first || g.local != local) {
		reject("session_summary_identity_conflict")
		return
	}
	g.tuple, g.first, g.local = tuple, first, local
	identity := scope.AssetID + "\x00" + scope.DeviceID + "\x00" + sid
	if previous := a.identities[identity]; previous != nil && (previous.scope != scope || previous.tuple != tuple || previous.first != first) {
		previous.problem = "session_summary_identity_conflict"
		reject("session_summary_identity_conflict")
		return
	}
	a.identities[identity] = g
	row := providerSessionRow{id: h.ID, last: last}
	for i, field := range []string{"client_packets", "server_packets", "client_wire_bytes", "server_wire_bytes", "hit_count"} {
		if summary[field] == nil { // producer omitempty means a zero counter
			continue
		}
		v, valid := strictUint(summary[field])
		if !valid {
			reject("session_summary_counter_invalid")
			return
		}
		row.counts[i] = v
	}
	if row.counts[4] == 0 || row.counts[0] == 0 && row.counts[2] != 0 || row.counts[1] == 0 && row.counts[3] != 0 || row.counts[0] == 0 && row.counts[1] == 0 {
		reject("session_summary_counter_invalid")
		return
	}
	g.rows = append(g.rows, row)
	// Summary client is a transport role, not the packet's current src side or
	// top-level direction hint. Only actual, tuple-bound protocol evidence wins.
	if client := providerSessionClient(h, m, input); client != "" {
		if client != endpoints[0] && client != endpoints[1] {
			reject("session_summary_client_tuple_conflict")
			return
		}
		g.clients[client] = true
	}
}

func providerSessionClient(h store.Hit, m map[string]any, input evidence.Input) string {
	packet := nestedMap(m, "raw_packet")
	if asString(packet["packet_hex"]) != "" {
		checked, problem := snapshotFramePayload(packet, m, &input)
		_, full, why := snapshotPayload(checked)
		captured, err := time.Parse(time.RFC3339Nano, asString(packet["capture_time"]))
		if problem == "" && full && why == "" && err == nil && captured.Equal(h.OccurredAt) {
			frame, err := snapshotDecodeFrame(m, asString(packet["packet_hex"]))
			if err == nil && frame.ErrorLayer() == nil {
				if tcp, ok := frame.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && tcp.SYN && !tcp.ACK {
					return net.JoinHostPort(asString(m["src_ip"]), strconv.Itoa(int(tcp.SrcPort)))
				}
			}
		}
	}
	// This function reuses providerVerifiedHTTP's per-hit cached reconstruction.
	if x := providerVerifiedHTTP(m); x != nil && x.requestSide != nil && x.Request != nil && providerExchangeInWindow(x, &input) {
		return net.JoinHostPort(x.requestSide.src, strconv.Itoa(int(x.requestSide.sp)))
	}
	return ""
}

func providerSessionRowLess(a, b providerSessionRow) bool {
	if a.last != b.last {
		return a.last < b.last
	}
	for i := range a.counts {
		if a.counts[i] != b.counts[i] {
			return a.counts[i] < b.counts[i]
		}
	}
	return a.id > b.id // stable smallest source ID wins equal maximal rows
}

func (a *providerSessionAccumulator) apply(out *SnapshotEvidenceInput) {
	indices := map[evidence.Scope]int{}
	for i := range out.Request.Inputs {
		indices[out.Request.Inputs[i].Scope] = i
	}
	keys := make([]string, 0, len(a.groups))
	for key := range a.groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := a.groups[key]
		if g.problem != "" || len(g.rows) == 0 {
			continue
		}
		sort.Slice(g.rows, func(i, j int) bool { return providerSessionRowLess(g.rows[i], g.rows[j]) })
		ids := []string{}
		seen := map[string]providerSessionRow{}
		valid := true
		for i, row := range g.rows {
			if old, ok := seen[row.id]; ok && (old.last != row.last || old.counts != row.counts) {
				valid = false
			}
			seen[row.id] = row
			ids = append(ids, row.id)
			if i > 0 {
				for j := range row.counts {
					if row.counts[j] < g.rows[i-1].counts[j] {
						valid = false
					}
				}
			}
		}
		if !valid {
			a.issue(g.rows[len(g.rows)-1].id, g.scope, "session_summary_non_monotonic")
			continue
		}
		if len(g.clients) != 1 {
			a.issue(g.rows[0].id, g.scope, "session_summary_client_role_unverified")
			continue
		}
		client := ""
		for c := range g.clients {
			client = c
		}
		last := g.rows[len(g.rows)-1]
		up, down := last.counts[2], last.counts[3]
		if client != g.local {
			up, down = down, up
		}
		index, ok := indices[g.scope]
		if !ok || out.Request.Inputs[index].Network == nil {
			continue
		}
		out.Request.Inputs[index].Network.Sessions = append(out.Request.Inputs[index].Network.Sessions, evidence.Session{SourceID: last.id, ID: g.id, Start: time.UnixMicro(int64(g.first)).UTC(), End: time.UnixMicro(int64(last.last)).UTC(), UpBytes: up, DownBytes: down, HitIDs: uniqueSortedStrings(ids), VolumeVerified: false, ByteUnit: "wire", ObservationOnly: true})
	}
	for _, issue := range a.issues {
		out.Manifest.addIssue(issue)
	}
	if omitted := a.issueCount - len(a.issues); omitted > 0 {
		out.Manifest.IssueCount += omitted
		out.Manifest.OmittedIssues += omitted
	}
	// The caller may aggregate these records, but no observation here changes
	// coverage, protocol contacts, outcome verification or volume authority.
}
