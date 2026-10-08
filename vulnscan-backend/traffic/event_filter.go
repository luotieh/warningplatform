package traffic

import (
	"net"
	"strings"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// Display-dependent filters run before pagination and are shared by rank counts.
// Do not apply the store's raw JSON substring filters first: those are not a
// superset of keyword tokens, displayed peers, or addresses inside a subnet.
func (s *EventService) matchingDisplayEvents(q store.EventQuery) ([]domain.Event, error) {
	base := q
	base.Keyword, base.Asset, base.OnlyAssetRelated = "", "", false
	events, err := s.core.Store.ListEventsMatching(base)
	if err != nil {
		return nil, err
	}
	var assets []domain.Asset
	if q.OnlyAssetRelated && strings.TrimSpace(q.Asset) == "" {
		assets = s.core.Store.ListAssets()
	}
	out := make([]domain.Event, 0, len(events))
	for _, event := range events {
		row := lyCompatibleEvent(event)
		if !matchesIOCHistory(row, q) {
			continue
		}
		if !matchesDisplayKeyword(row, eventRankDimensions(event, row)["typeText"], q.Keyword) {
			continue
		}
		if strings.TrimSpace(q.Asset) != "" {
			if !matchesDisplayAsset(q.Asset, row) {
				continue
			}
		} else if q.OnlyAssetRelated {
			hit := false
			for _, asset := range assets {
				if asset.Status == 1 && matchesDisplayAsset(asset.Address, row) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		out = append(out, event)
	}
	return out, nil
}

func matchesIOCHistory(row map[string]any, q store.EventQuery) bool {
	ioc, _ := row["ioc"].(map[string]any)
	for _, pair := range [][2]string{
		{q.IOCValue, stringValue(ioc["ioc_value"])},
		{q.IOCType, stringValue(ioc["ioc_type"])},
		{q.Victim, stringValue(row["victimDevice"])},
	} {
		if want := strings.TrimSpace(pair[0]); want != "" && !strings.EqualFold(want, strings.TrimSpace(pair[1])) {
			return false
		}
	}
	return true
}

func matchesDisplayKeyword(row map[string]any, typeText, keyword string) bool {
	tokens := strings.Fields(strings.ToLower(keyword))
	if len(tokens) == 0 {
		return true
	}
	fields := []string{typeText}
	for _, key := range []string{"attackDevice", "victimDevice", "desc", "rule_desc", "type", "event_id"} {
		fields = append(fields, stringValue(row[key]))
	}
	if ioc, ok := row["ioc"].(map[string]any); ok {
		fields = append(fields, stringValue(ioc["ioc_value"]), stringValue(ioc["ioc_type"]))
	}
	if files, ok := row["evidence_files"].([]any); ok {
		for _, file := range files {
			if f, ok := file.(map[string]any); ok {
				fields = append(fields, stringValue(f["name"]))
			}
		}
	}
	hay := strings.ToLower(strings.Join(fields, " "))
	for _, token := range tokens {
		if !strings.Contains(hay, token) {
			return false
		}
	}
	return true
}

func matchesDisplayAsset(address string, row map[string]any) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return false
	}
	for _, key := range []string{"attackDevice", "victimDevice"} {
		peer := strings.ToLower(strings.TrimSpace(stringValue(row[key])))
		if strings.Contains(address, "/") {
			_, subnet, err := net.ParseCIDR(normalizeAddrForType("ip_segment", address))
			if err == nil && subnet.Contains(net.ParseIP(peer)) {
				return true
			}
		} else if peer == address {
			return true
		}
	}
	return false
}
