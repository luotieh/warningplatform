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

func TestNormalizeAccessAddressFixesSpacedScheme(t *testing.T) {
	got, err := NormalizeAccessAddress("http: //oa.example.com", "domain_site")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://oa.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeAccessAddressAddsHTTPForDomain(t *testing.T) {
	got, err := NormalizeAccessAddress("jspxxw.com", "domain_site")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://jspxxw.com" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeAccessAddressRejectsMultiple(t *testing.T) {
	_, err := NormalizeAccessAddress("http://a.com, http://b.com", "")
	if err == nil {
		t.Fatal("expected error for multiple addresses")
	}
}

func TestNormalizeAccessAddressKeepsIPv4Port(t *testing.T) {
	got, err := NormalizeAccessAddress("49.65.127.74:99", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "49.65.127.74:99" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyDerivedNetworkFieldsFromURL(t *testing.T) {
	item := &model.Asset{
		Address:     "http://peixian.cm.jstv.com/path",
		AssetFamily: "domain_site",
	}
	normalizeAssetAddressFields(item)
	if item.Domain != "peixian.cm.jstv.com" {
		t.Fatalf("domain=%q", item.Domain)
	}
	if item.URL == "" {
		t.Fatal("expected url")
	}
	if item.Protocol != "http" {
		t.Fatalf("protocol=%q", item.Protocol)
	}
}

func TestApplyDerivedNetworkFieldsFromIPv4Port(t *testing.T) {
	item := &model.Asset{Address: "49.65.127.74:99"}
	normalizeAssetAddressFields(item)
	if item.IPv4 != "49.65.127.74" {
		t.Fatalf("ipv4=%q", item.IPv4)
	}
	if item.Port != 99 {
		t.Fatalf("port=%d", item.Port)
	}
}
