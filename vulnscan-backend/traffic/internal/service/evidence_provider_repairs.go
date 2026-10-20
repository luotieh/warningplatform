package service

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

// The legacy exact relation checks explicit http_host/DNS/SNI. An absolute,
// persisted request URL also proves its host; an IOC label alone never does.
func providerHistoryRelation(c map[string]any, relation store.HistoryRelation) bool {
	if store.ExactHistoryRelation(c, relation) {
		return true
	}
	if relation.IOC.Type != "domain" {
		return false
	}
	ioc := nestedMap(c, "ioc")
	if asString(ioc["ioc_type"]) != relation.IOC.Type || asString(ioc["ioc_value"]) != relation.IOC.Value {
		return false
	}
	if asString(c["src_ip"]) != relation.Address && asString(c["dst_ip"]) != relation.Address {
		return false
	}
	u, err := url.Parse(asString(nestedMap(c, "app")["http_url"]))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil && strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(relation.IOC.Value, "."))
}

func populateProviderGroup(g *evidence.GroupInput, req evidence.Request, members map[string]evidence.Scope) error {
	hits := map[string]evidence.Hit{}
	for _, h := range req.Hits {
		hits[h.ID] = h
	}
	seenConnections, seenDNS := map[string]bool{}, map[string]bool{}
	for _, in := range req.Inputs {
		if in.Scope.EndpointID != g.Endpoint {
			continue
		}
		if in.Network != nil {
			for _, c := range in.Network.Connections {
				s, ok := members[c.SourceID]
				if !ok {
					continue
				}
				h, exists := hits[c.SourceID]
				endpoint := c.Transport + "://" + net.JoinHostPort(c.Destination, fmt.Sprint(c.Port))
				if !exists || s != in.Scope || h.Scope != s || c.AssetID != s.AssetID || !c.Time.Equal(h.OccurredAt) || endpoint != g.Endpoint || seenConnections[c.SourceID] || c.Time.Before(g.Window.Start) || !c.Time.Before(g.Window.End) {
					return fmt.Errorf("provider_group_connection_binding_invalid")
				}
				seenConnections[c.SourceID] = true
				g.Connections = append(g.Connections, c)
			}
		}
		if in.DNS != nil {
			for _, d := range in.DNS.Records {
				s, ok := members[d.SourceID]
				if !ok {
					continue
				}
				h, exists := hits[d.SourceID]
				if !exists || s != in.Scope || h.Scope != s || !d.Time.Equal(h.OccurredAt) || seenDNS[d.SourceID] || d.Time.Before(g.Window.Start) || !d.Time.Before(g.Window.End) {
					return fmt.Errorf("provider_group_dns_binding_invalid")
				}
				seenDNS[d.SourceID] = true
				g.DNS = append(g.DNS, d)
				g.DNSOwnership[d.SourceID] = s.AssetID
			}
		}
	}
	return nil
}

func buildProviderAssetInputs(req *evidence.Request) {
	buildSnapshotAssetInputs(req)
	// The shared builder assumes the legacy collector verified provenance.
	// Preserve the stricter independent provider's per-family proof instead.
	for i := range req.AssetInputs {
		a := &req.AssetInputs[i]
		for _, in := range req.Inputs {
			if in.Scope.AssetID != a.Scope.AssetID || in.Scope.DeviceID != a.Scope.DeviceID {
				continue
			}
			if a.Network != nil && in.Network != nil {
				a.Network.Verified = a.Network.Verified && in.Network.Verified
				a.Network.Complete = a.Network.Complete && in.Network.Complete
			}
			if a.DNS != nil && in.DNS != nil {
				a.DNS.Verified = a.DNS.Verified && in.DNS.Verified
				a.DNS.Complete = a.DNS.Complete && in.DNS.Complete
			}
		}
		if a.Network != nil {
			a.Network.SourceIDs = uniqueSortedStrings(a.Network.SourceIDs)
		}
		if a.DNS != nil {
			a.DNS.SourceIDs = uniqueSortedStrings(a.DNS.SourceIDs)
		}
	}
}
