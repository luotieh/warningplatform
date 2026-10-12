package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"strings"
	"time"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

// One bounded indexed batch for nearby DNS candidates, shared by all report
// scopes. Do not issue an individual query for each rule or historical event.
func (s Services) verifyReportHistoricalDNS(ctx context.Context, snap EvidenceSnapshot, h *ReportHistory) {
	h.RawDNSVerificationRequired = true
	h.RawDNSStatus = "not_applicable"
	// Verify nearby saved DNS candidates once; do not let representative
	// snapshot samples decide which full-membership SNI observations can join.
	// The final edge builder matches each full observation's actual SNI.
	sources := []string{}
	for _, row := range h.Rows {
		if asString(row.Application["dns_query"]) != "" && !row.Last.Before(h.End.Add(-5*time.Minute)) {
			sources = append(sources, row.EventID)
		}
	}
	if len(sources) == 0 {
		h.RawDNSStatus = "no_nearby_dns_candidate"
		return
	}
	if snap.Watermark <= 0 {
		h.RawDNSStatus = "history_raw_watermark_unavailable"
		return
	}
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hits, err := s.Store.HitPage(readCtx, store.HitQuery{Sources: sources, Watermark: snap.Watermark, From: h.End.Add(-5 * time.Minute), To: h.End, Limit: 500})
	if err != nil {
		h.RawDNSStatus = "history_raw_read_failed"
		return
	}
	h.RawDNSReadHits = len(hits)
	if len(hits) == 500 {
		h.RawDNSStatus = "history_raw_hit_budget_exceeded"
		return
	}
	bytesRead := 0
	verified := 0
	for _, hit := range hits {
		bytesRead += len(hit.Raw)
		if bytesRead > 2<<20 {
			h.RawDNSStatus = "history_raw_byte_budget_exceeded"
			return
		}
		var m map[string]any
		decoder := json.NewDecoder(bytes.NewReader(hit.Raw))
		decoder.UseNumber()
		if decoder.Decode(&m) != nil {
			continue
		}
		reportVerifyDatagram(m)
		packet := nestedMap(m, "raw_packet")
		if packet["report_quality_derivation"] == nil || asString(m["protocol"]) != "udp" {
			continue
		}
		if _, problem := snapshotFramePayload(packet, m, &evidence.Input{}); problem != "" {
			continue
		}
		raw, err := hex.DecodeString(asString(packet["payload_hex"]))
		if err != nil {
			continue
		}
		var message dnsmessage.Message
		if message.Unpack(raw) != nil || message.Truncated || !message.Header.Response || len(message.Questions) != 1 {
			continue
		}
		query := strings.TrimSuffix(strings.ToLower(message.Questions[0].Name.String()), ".")
		answers := map[string]bool{}
		for _, answer := range message.Answers {
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				answers[net.IP(body.A[:]).String()] = true
			case *dnsmessage.AAAAResource:
				answers[net.IP(body.AAAA[:]).String()] = true
			}
		}
		for index := range h.Rows {
			row := &h.Rows[index]
			// Hit storage is DATETIME(6); compare the event bounds at that same
			// precision rather than rejecting a matching sub-microsecond source.
			if row.EventID != hit.EventID || row.DeviceID != asString(m["device_id"]) || row.SourceAddress != asString(m["src_ip"]) || row.DestinationAddress != asString(m["dst_ip"]) || query != strings.ToLower(asString(row.Application["dns_query"])) || hit.OccurredAt.Before(row.First.Truncate(time.Microsecond)) || hit.OccurredAt.After(row.Last.Truncate(time.Microsecond)) {
				continue
			}
			supplied, ok := row.Application["dns_answers"].([]any)
			if !ok || len(supplied) == 0 {
				continue
			}
			consistent := true
			for _, answer := range supplied {
				if !answers[asString(answer)] {
					consistent = false
				}
			}
			if consistent {
				row.VerifiedDNSHitIDs = append(row.VerifiedDNSHitIDs, hit.ID)
				verified++
			}
		}
	}
	if verified == 0 {
		h.RawDNSStatus = "history_raw_dns_not_verified"
	} else {
		h.RawDNSStatus = "verified_nearby_dns"
	}
}
