package asset

import (
	"testing"

	"vulnscan-backend/model"
)

func TestNormalizeAssetAddressFieldsFromIPv4(t *testing.T) {
	item := &model.Asset{IPv4: "223.5.5.5"}
	normalizeAssetAddressFields(item)
	if item.Address != "223.5.5.5" {
		t.Fatalf("address=%q", item.Address)
	}
}

func TestNormalizeAssetAddressFieldsKeepsExisting(t *testing.T) {
	item := &model.Asset{Address: "https://oa.example.com", IPv4: "10.0.0.1"}
	normalizeAssetAddressFields(item)
	if item.Address != "https://oa.example.com" {
		t.Fatalf("address=%q", item.Address)
	}
}
