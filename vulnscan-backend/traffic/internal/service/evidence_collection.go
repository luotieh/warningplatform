package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const EvidenceCollectionSchemaVersion = "evidence-platform-collection-1"

// EvidenceCollection is the serializable collection/preprocessing boundary.
// Hits retain their original Raw bytes, including raw_packet and exchange.
// The digest detects accidental changes; it does not authenticate imported data.
// Query matches and snapshot membership are not claims of complete capture.
type EvidenceCollection struct {
	SchemaVersion     string                                `json:"schema_version"`
	CollectionDigest  string                                `json:"collection_digest"`
	Event             domain.Event                          `json:"event"`
	Snapshot          EvidenceSnapshot                      `json:"snapshot"`
	Assets            []domain.Asset                        `json:"assets"`
	Hits              []CollectedHit                        `json:"hits"`
	Window            evidence.AnalysisWindow               `json:"window"`
	Options           EvidenceQueryOptions                  `json:"options"`
	MatchAddresses    []string                              `json:"match_addresses"`
	MatchIOCs         []domain.IOC                          `json:"match_iocs"`
	HistoryCandidates []domain.Event                        `json:"history_candidates"`
	HistoryTruncated  bool                                  `json:"history_truncated"`
	HistorySnapshots  map[string]CollectedSnapshotReference `json:"history_snapshots"`
	GroupCandidates   []domain.Event                        `json:"group_candidates"`
	GroupTruncated    bool                                  `json:"group_truncated"`
	Peers             []CollectedTrafficSnapshot            `json:"peers"`
	SourceRegistry    *store.AggregateRecord                `json:"source_registry,omitempty"`
	Supplemental      *store.AggregateRecord                `json:"supplemental,omitempty"`
	Audit             EvidenceSupplyAudit                   `json:"audit"`
}

type CollectedSnapshotReference struct {
	EventID  string           `json:"event_id"`
	Snapshot EvidenceSnapshot `json:"snapshot"`
	Reason   string           `json:"unavailable_reason,omitempty"`
	Hits     []CollectedHit   `json:"hits,omitempty"`
	Loaded   bool             `json:"loaded"`
}

type CollectedTrafficSnapshot struct {
	Event    domain.Event     `json:"event"`
	Snapshot EvidenceSnapshot `json:"snapshot"`
	Hits     []CollectedHit   `json:"hits"`
}

// Raw is encoded as base64 bytes at this boundary. json.RawMessage would
// normalize source JSON whitespace/escaping during serialization and change
// raw-byte accounting when the saved collection is replayed.
type CollectedHit store.Hit

func (h CollectedHit) MarshalJSON() ([]byte, error) {
	type metadata CollectedHit
	return json.Marshal(struct {
		metadata
		Raw []byte `json:"raw"`
	}{metadata(h), h.Raw})
}

func (h *CollectedHit) UnmarshalJSON(raw []byte) error {
	type metadata CollectedHit
	var wire struct {
		metadata
		Raw []byte `json:"raw"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*h = CollectedHit(wire.metadata)
	h.Raw = wire.Raw
	return nil
}

func collectEvidenceHits(hits []store.Hit) []CollectedHit {
	if hits == nil {
		return nil
	}
	out := make([]CollectedHit, len(hits))
	for i, hit := range hits {
		out[i] = CollectedHit(hit)
	}
	return out
}

func collectedStoreHits(hits []CollectedHit) []store.Hit {
	if hits == nil {
		return nil
	}
	out := make([]store.Hit, len(hits))
	for i, hit := range hits {
		out[i] = store.Hit(hit)
	}
	return out
}

func (c *EvidenceCollection) Seal() {
	c.CollectionDigest = ""
	c.CollectionDigest = digest(*c)
}

func (c EvidenceCollection) Validate() error {
	if c.SchemaVersion != EvidenceCollectionSchemaVersion {
		return fmt.Errorf("collection_schema_version_mismatch")
	}
	expected := c.CollectionDigest
	c.CollectionDigest = ""
	if expected == "" || expected != digest(c) {
		return fmt.Errorf("collection_digest_mismatch")
	}
	if c.Event.EventID == "" || c.Snapshot.EventID != c.Event.EventID || c.Audit.EventID != c.Event.EventID || c.Snapshot.Version <= 0 || !c.Window.Start.Before(c.Window.End) {
		return fmt.Errorf("collection_event_snapshot_binding_mismatch")
	}
	_, err := providerOptions(c.Options)
	return err
}

func cloneEvidenceCollection(c EvidenceCollection) (EvidenceCollection, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return EvidenceCollection{}, err
	}
	var out EvidenceCollection
	err = json.Unmarshal(raw, &out)
	if err != nil {
		return EvidenceCollection{}, err
	}
	// json.RawMessage marshaling can normalize whitespace and escaping. Keep
	// the original JSON bytes as well as the decoded metadata in memory.
	for i := range out.Hits {
		out.Hits[i].Raw = append(json.RawMessage(nil), c.Hits[i].Raw...)
	}
	for i := range out.Audit.StoredHits {
		out.Audit.StoredHits[i].Raw = append(json.RawMessage(nil), c.Audit.StoredHits[i].Raw...)
	}
	for i := range out.Peers {
		for j := range out.Peers[i].Hits {
			out.Peers[i].Hits[j].Raw = append(json.RawMessage(nil), c.Peers[i].Hits[j].Raw...)
		}
	}
	if out.SourceRegistry != nil {
		out.SourceRegistry.Value = append(json.RawMessage(nil), c.SourceRegistry.Value...)
	}
	if out.Supplemental != nil {
		out.Supplemental.Value = append(json.RawMessage(nil), c.Supplemental.Value...)
	}
	return out, err
}

// This inspects saved routing metadata only to plan bounded platform queries.
// It does not parse packets, build contacts or construct any Bundle inputs.
func providerCollectionKeys(event domain.Event, snap EvidenceSnapshot, assets []domain.Asset, hits []store.Hit) ([]string, []domain.IOC, error) {
	addresses := []string{}
	iocs := historyIOCs(event, snap.Context)
	for _, hit := range hits {
		raw := map[string]any{}
		decoder := json.NewDecoder(bytes.NewReader(hit.Raw))
		decoder.UseNumber()
		if err := decoder.Decode(&raw); err != nil {
			return nil, nil, fmt.Errorf("saved_hit_json_invalid:%s", hit.ID)
		}
		scope, remote, _, ok := snapshotScope(raw, assets)
		if !ok {
			continue
		}
		for _, field := range []string{"src_ip", "dst_ip"} {
			address := asString(raw[field])
			if id, ok := registeredSnapshotAsset(assets, address); ok && id == scope.AssetID {
				addresses = append(addresses, address)
			}
		}
		ioc, field := providerStoredIOCField(raw, remote)
		if field != "" {
			iocs = append(iocs, ioc)
		}
	}
	index := map[string]domain.IOC{}
	for _, ioc := range iocs {
		index[ioc.Type+":"+ioc.Value] = ioc
	}
	iocs = nil
	for _, ioc := range index {
		iocs = append(iocs, ioc)
	}
	sort.Slice(iocs, func(i, j int) bool { return iocs[i].Type+":"+iocs[i].Value < iocs[j].Type+":"+iocs[j].Value })
	return uniqueSortedStrings(addresses), iocs, nil
}

// A stored association is enough for query routing, but does not prove an
// independent communication, full transaction or complete observation window.
func providerStoredIOCField(raw map[string]any, remote string) (domain.IOC, string) {
	stored := nestedMap(raw, "ioc")
	ioc := domain.IOC{Type: firstNonEmpty(asString(raw["ioc_type"]), asString(stored["ioc_type"])), Value: firstNonEmpty(asString(raw["ioc_value"]), asString(stored["ioc_value"]))}
	app := nestedMap(raw, "app")
	field := ""
	switch ioc.Type {
	case "ip":
		if remote == ioc.Value {
			field = "flow.remote.ip"
		}
	case "domain", "url":
		rawURL := asString(app["http_url"])
		u, err := url.Parse(rawURL)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" {
			if ioc.Type == "url" && rawURL == ioc.Value {
				field = "http.request.url"
			}
			if ioc.Type == "domain" && strings.EqualFold(u.Hostname(), ioc.Value) {
				field = "http.request.host"
			}
		}
		if ioc.Type == "domain" && strings.EqualFold(strings.TrimSuffix(asString(app["dns_query"]), "."), strings.TrimSuffix(ioc.Value, ".")) && strings.TrimSpace(asString(app["dns_query"])) != "" {
			field = "dns.question.name"
		}
	}
	return ioc, field
}
