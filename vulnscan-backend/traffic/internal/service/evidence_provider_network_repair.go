package service

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
)

// Reuse exact, active registry addresses already collected for this analysis.
// A network prefix is not a host address, and this does not certify coverage,
// member roles, NAT identity, or a connection between two registered assets.
func populateProviderMemberAddresses(req *evidence.Request, assets []domain.Asset) {
	owners := map[string]map[string]bool{}
	for _, a := range assets {
		ip, err := netip.ParseAddr(strings.TrimSpace(a.Address))
		if err != nil || a.ID == "" || a.Status != 1 {
			continue
		}
		address := ip.Unmap().String()
		if owners[address] == nil {
			owners[address] = map[string]bool{}
		}
		owners[address][a.ID] = true
	}
	byAsset := map[string][]string{}
	for address, ids := range owners {
		if len(ids) == 1 {
			for id := range ids {
				byAsset[id] = append(byAsset[id], address)
			}
		}
	}
	hits := map[string]evidence.Hit{}
	for _, h := range req.Hits {
		hits[h.ID] = h
	}
	for i := range req.Groups {
		g := &req.Groups[i]
		if !strings.HasPrefix(g.ID, "candidate:") {
			continue
		}
		for j := range g.Members {
			m := &g.Members[j]
			valid := m.MembershipVerified && m.AssetID != "" && m.AssetID == m.Scope.AssetID && len(m.HitIDs) > 0
			for _, id := range m.HitIDs {
				h, ok := hits[id]
				valid = valid && ok && h.Scope == m.Scope
			}
			if valid {
				m.Addresses = uniqueSortedStrings(append(m.Addresses, byAsset[m.AssetID]...))
			}
		}
	}
}

// Summarize only this member's source-bound observations. Counts deliberately
// describe saved observations, not independent connections or attack outcomes.
// Examples are capped so a large group cannot expand semantic input unboundedly.
func providerGroupMemberSummary(g evidence.GroupInput, member evidence.GroupMember, hits map[string]evidence.Hit) string {
	base := fmt.Sprintf("资产=%s；核验角色=%s；保存关联命中%d条", member.AssetID, member.Role, len(member.HitIDs))
	if !trustedInputProvenance(g.Provenance) || !member.MembershipVerified || member.AssetID == "" || member.AssetID != member.Scope.AssetID || !g.Window.Start.Before(g.Window.End) {
		return base + "；实际行为未提供或未核验"
	}
	allowed := map[string]bool{}
	for _, id := range member.HitIDs {
		h, ok := hits[id]
		if id == "" || !ok || allowed[id] || h.Scope != member.Scope || h.OccurredAt.IsZero() || h.OccurredAt.Before(g.Window.Start) || !h.OccurredAt.Before(g.Window.End) {
			return base + "；实际行为来源绑定不足"
		}
		allowed[id] = true
	}
	bound := func(id string, at time.Time) bool {
		h, ok := hits[id]
		return ok && allowed[id] && !at.IsZero() && h.OccurredAt.Equal(at)
	}
	connections, dns := 0, 0
	endpoints, domains := map[string]bool{}, map[string]bool{}
	seenConnections, seenDNS := map[string]bool{}, map[string]bool{}
	var first, last time.Time
	observe := func(at time.Time) {
		if first.IsZero() || at.Before(first) {
			first = at
		}
		if last.IsZero() || at.After(last) {
			last = at
		}
	}
	for _, c := range g.Connections {
		if !bound(c.SourceID, c.Time) || c.AssetID != member.AssetID || seenConnections[c.SourceID] {
			continue
		}
		ip, err := netip.ParseAddr(c.Destination)
		transport := strings.ToLower(c.Transport)
		if err != nil || c.Port == 0 || (transport != "tcp" && transport != "udp") {
			continue
		}
		endpoint := transport + "://" + net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(int(c.Port)))
		if hits[c.SourceID].Scope.EndpointID != endpoint {
			continue
		}
		seenConnections[c.SourceID] = true
		connections++
		endpoints[endpoint] = true
		observe(c.Time)
	}
	for _, d := range g.DNS {
		if !bound(d.SourceID, d.Time) || g.DNSOwnership[d.SourceID] != member.AssetID || seenDNS[d.SourceID] || strings.TrimSpace(d.Domain) == "" || len(d.Domain) > 253 || strings.ContainsAny(d.Domain, "\r\n\x00") {
			continue
		}
		seenDNS[d.SourceID] = true
		dns++
		domains[d.Domain] = true
		observe(d.Time)
	}
	if connections+dns == 0 {
		return base + "；实际行为未提供或未核验"
	}
	examples := func(values map[string]bool) string {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 3 {
			keys = keys[:3]
		}
		return strings.Join(keys, ",")
	}
	return fmt.Sprintf("%s；本组绑定通信观测%d条、DNS观测%d条；保存时间范围=%s至%s；目的端点示例=%s；DNS域示例=%s；仅描述保存观测，条数不代表独立连接次数，不证明行为成功", base, connections, dns, first.UTC().Format(time.RFC3339Nano), last.UTC().Format(time.RFC3339Nano), examples(endpoints), examples(domains))
}
