package asm

import (
	"context"
	"fmt"
	"time"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type PortExposureCollector struct {
	db *gorm.DB
}

func NewPortExposureCollector(db *gorm.DB) *PortExposureCollector {
	return &PortExposureCollector{db: db}
}

func (c *PortExposureCollector) Name() string { return "port-exposure" }

func (c *PortExposureCollector) Collect(ctx context.Context, seed Seed) ([]DiscoveredAsset, error) {
	if c.db == nil {
		return nil, nil
	}

	targets := buildSeedTargets(seed)
	if len(targets) == 0 {
		return nil, nil
	}

	var findings []model.ScanFinding
	q := c.db.WithContext(ctx).
		Model(&model.ScanFinding{}).
		Where("target IN ? AND type = ?", targets, "port_open").
		Order("created_at DESC").
		Limit(500)
	if err := q.Find(&findings).Error; err != nil {
		return nil, fmt.Errorf("port-exposure: query findings: %w", err)
	}

	now := time.Now()
	seen := make(map[string]bool)
	var assets []DiscoveredAsset

	for _, f := range findings {
		key := fmt.Sprintf("%s:%d", f.Target, f.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		attrs := map[string]string{
			"port":     fmt.Sprintf("%d", f.Port),
			"protocol": f.Protocol,
			"source":   "scan-finding",
		}
		if f.Title != "" {
			attrs["service"] = f.Title
		}

		assets = append(assets, DiscoveredAsset{
			Type:       "service",
			Value:      key,
			Source:     "port-scan",
			Attributes: attrs,
			FirstSeen:  f.CreatedAt,
			LastSeen:   now,
			Status:     "active",
		})
	}

	return assets, nil
}

func buildSeedTargets(seed Seed) []string {
	switch seed.Type {
	case "domain", "ip", "url":
		return []string{seed.Value}
	default:
		return nil
	}
}
