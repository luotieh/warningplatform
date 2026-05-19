package sitemonitor

import (
	"testing"

	"vulnscan-backend/model"
)

func TestResolvePathTaskURL_Domain(t *testing.T) {
	target := &model.MonitorTarget{
		TargetType:    model.MonitorTargetTypeDomain,
		TargetValue:   "example.com",
		DefaultScheme: "https",
	}
	path := &model.MonitorPathTask{Path: "/news"}
	ep, err := ResolvePathTaskURL(target, path)
	if err != nil {
		t.Fatal(err)
	}
	if ep.RequestURL != "https://example.com/news" {
		t.Fatalf("url=%s", ep.RequestURL)
	}
}

func TestResolvePathTaskURL_IPVirtualHost(t *testing.T) {
	target := &model.MonitorTarget{
		TargetType:    model.MonitorTargetTypeIP,
		TargetValue:   "203.0.113.10",
		VirtualHost:   "www.example.com",
		DefaultScheme: "https",
	}
	path := &model.MonitorPathTask{Path: "/"}
	ep, err := ResolvePathTaskURL(target, path)
	if err != nil {
		t.Fatal(err)
	}
	if ep.RequestURL != "https://203.0.113.10/" {
		t.Fatalf("url=%s", ep.RequestURL)
	}
	if ep.RequestHost != "www.example.com" {
		t.Fatalf("host=%s", ep.RequestHost)
	}
}

func TestResolvePathTaskURL_Override(t *testing.T) {
	target := &model.MonitorTarget{TargetType: model.MonitorTargetTypeDomain, TargetValue: "a.com"}
	path := &model.MonitorPathTask{URLOverride: "https://other.com/x"}
	ep, err := ResolvePathTaskURL(target, path)
	if err != nil {
		t.Fatal(err)
	}
	if ep.RequestURL != "https://other.com/x" {
		t.Fatalf("url=%s", ep.RequestURL)
	}
}
