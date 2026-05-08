package asm

import (
	"log/slog"
	"time"
)

type DiffEngine struct{}

func NewDiffEngine() *DiffEngine {
	return &DiffEngine{}
}

func (d *DiffEngine) Compare(prev, current []DiscoveredAsset) []AssetChange {
	prevMap := buildAssetMap(prev)
	currMap := buildAssetMap(current)

	var changes []AssetChange

	for key, currAsset := range currMap {
		if _, exists := prevMap[key]; !exists {
			changes = append(changes, AssetChange{
				AssetID:  currAsset.ID,
				Field:    "status",
				OldValue: "",
				NewValue: "new",
				ChangeAt: time.Now(),
				Severity: classifyChangeSeverity("new", currAsset),
			})
		}
	}

	for key, prevAsset := range prevMap {
		if _, exists := currMap[key]; !exists {
			changes = append(changes, AssetChange{
				AssetID:  prevAsset.ID,
				Field:    "status",
				OldValue: "active",
				NewValue: "removed",
				ChangeAt: time.Now(),
				Severity: "info",
			})
		}
	}

	for key, currAsset := range currMap {
		if prevAsset, exists := prevMap[key]; exists {
			attrChanges := compareAttributes(prevAsset, currAsset)
			changes = append(changes, attrChanges...)
		}
	}

	slog.Info("[*] ASM变更检测完成",
		"prev_count", len(prev),
		"current_count", len(current),
		"changes", len(changes),
	)

	return changes
}

func buildAssetMap(assets []DiscoveredAsset) map[string]DiscoveredAsset {
	m := make(map[string]DiscoveredAsset)
	for _, a := range assets {
		key := a.Type + "|" + a.Value
		m[key] = a
	}
	return m
}

func compareAttributes(prev, curr DiscoveredAsset) []AssetChange {
	var changes []AssetChange

	for key, newVal := range curr.Attributes {
		oldVal := prev.Attributes[key]
		if oldVal != newVal {
			changes = append(changes, AssetChange{
				AssetID:  curr.ID,
				Field:    "attr." + key,
				OldValue: oldVal,
				NewValue: newVal,
				ChangeAt: time.Now(),
				Severity: classifyAttrChangeSeverity(key),
			})
		}
	}

	return changes
}

func classifyChangeSeverity(changeType string, asset DiscoveredAsset) string {
	switch changeType {
	case "new":
		if asset.Type == "ip" || asset.Type == "url" {
			return "medium"
		}
		return "low"
	default:
		return "info"
	}
}

func classifyAttrChangeSeverity(field string) string {
	highSeverity := map[string]bool{
		"open_ports": true, "services": true, "tls_version": true,
	}
	if highSeverity[field] {
		return "high"
	}
	return "low"
}
