package dashboard

import (
	"context"
	"testing"

	"code.yt-security.com/public/access/permission"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

func TestGetSecurityPostureScopesVulnsByVisibleAssets(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&model.Asset{},
		&model.Vulnerability{},
		&model.ScanTask{},
		&model.WorkerNode{},
		&model.Alert{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	assets := []model.Asset{
		{ID: "asset-org-a", Name: "Org A Asset", Address: "10.0.0.1", OrganizeID: "org-a", RiskScore: 80},
		{ID: "asset-org-b", Name: "Org B Asset", Address: "10.0.0.2", OrganizeID: "org-b", RiskScore: 99},
	}
	if err := db.Create(&assets).Error; err != nil {
		t.Fatalf("seed assets: %v", err)
	}

	vulns := []model.Vulnerability{
		{ID: "vuln-a-critical", AssetID: "asset-org-a", Target: "10.0.0.1", Title: "A critical", Severity: "critical", OrganizeID: "org-a"},
		{ID: "vuln-a-high", AssetID: "asset-org-a", Target: "10.0.0.1", Title: "A high", Severity: "high", OrganizeID: "org-a"},
		{ID: "vuln-b-critical", AssetID: "asset-org-b", Target: "10.0.0.2", Title: "B critical", Severity: "critical", OrganizeID: "org-b"},
	}
	if err := db.Create(&vulns).Error; err != nil {
		t.Fatalf("seed vulns: %v", err)
	}

	scope := permission.GormScope(&permission.DataScope{
		Scope:       permission.ScopeOrganize,
		OrganizeIDs: []string{"org-a"},
	}, "", permission.FieldMapping{OrganizeIDColumn: "organize_id"})

	posture, err := NewAggregator(db).GetSecurityPosture(context.Background(), scope)
	if err != nil {
		t.Fatalf("get posture: %v", err)
	}

	if posture.TotalAssets != 1 {
		t.Fatalf("expected scoped asset count 1, got %d", posture.TotalAssets)
	}
	if posture.TotalVulns != 2 {
		t.Fatalf("expected scoped vuln count 2, got %d", posture.TotalVulns)
	}
	if posture.SeverityDist["critical"] != 1 {
		t.Fatalf("expected only one scoped critical vuln, got %d", posture.SeverityDist["critical"])
	}
	if len(posture.TopRiskAssets) != 1 || posture.TopRiskAssets[0].AssetID != "asset-org-a" {
		t.Fatalf("expected top risk assets scoped to org-a, got %#v", posture.TopRiskAssets)
	}
}
