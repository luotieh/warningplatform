package service

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

const semanticAdapterVersion = "snapshot-semantic-adapter-0.1"
const maxSemanticObservations = 128
const maxSemanticObservationBytes = 2 << 20
const maxSemanticMessageBytes = 32 << 10

// Captured during the single snapshot scan; never included in fact caches.
type SnapshotSemanticObservation struct {
	HitID         string
	Scope         evidence.Scope
	Direction     string
	Payload       string
	Response      string
	Body          string
	HTTP          *evidence.HTTPRecord
	DNS           *evidence.DNSRecord
	Complete      bool
	StratumMethod string
	TransactionID string
}

func collectSnapshotSemanticObservation(out *SnapshotEvidenceInput, input *evidence.Input, h store.Hit, m map[string]any, assets []domain.Asset) {
	o := SnapshotSemanticObservation{HitID: h.ID, Scope: input.Scope}
	if id, ok := registeredSnapshotAsset(assets, asString(m["src_ip"])); ok && id == input.Scope.AssetID {
		o.Direction = "outbound"
	} else if id, ok := registeredSnapshotAsset(assets, asString(m["dst_ip"])); ok && id == input.Scope.AssetID {
		o.Direction = "inbound"
	}
	if input.HTTP != nil {
		for _, r := range input.HTTP.Records {
			if r.SourceID == h.ID {
				copy := r
				o.HTTP = &copy
			}
		}
	}
	if input.DNS != nil {
		for _, r := range input.DNS.Records {
			if r.SourceID == h.ID {
				copy := r
				o.DNS = &copy
			}
		}
	}
	packet := nestedMap(m, "raw_packet")
	if child := nestedMap(packet, "request"); len(child) > 0 {
		packet = child
	}
	packet, frameProblem := snapshotFramePayload(packet, m, input)
	payload, full, problem := snapshotPayload(packet)
	if frameProblem != "" || (problem != "" && problem != "payload_bytes_unavailable") {
		return
	}
	if o.DNS != nil {
		var message dnsmessage.Message
		data := payload
		if strings.EqualFold(asString(m["protocol"]), "tcp") {
			if len(data) <= 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 {
				full = false
			} else {
				data = data[2:]
			}
		}
		o.Complete = full && message.Unpack(data) == nil && !message.Truncated && len(message.Questions) == 1 && strings.EqualFold(strings.TrimSuffix(message.Questions[0].Name.String(), "."), o.DNS.Domain)
	}
	if o.HTTP != nil && len(payload) > 0 && utf8.Valid(payload) {
		o.Payload = string(payload)
		o.Complete = full && !o.HTTP.Truncated
		// Parsed body belongs to the same actual request, not app sample fields.
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
		if err != nil {
			o.HTTP = nil
			o.Payload = ""
			o.Complete = false
		}
		if err == nil {
			o.DNS = nil // actual HTTP bytes must not inherit a conflicting DNS label
			body, readErr := io.ReadAll(io.LimitReader(req.Body, maxSemanticMessageBytes+1))
			req.Body.Close()
			if readErr == nil && utf8.Valid(body) && len(body) <= maxSemanticMessageBytes {
				o.Body = string(body)
			}
		}
		if o.HTTP != nil && o.HTTP.ResponseVerified {
			raw, complete, why := snapshotPayload(nestedMap(nestedMap(m, "raw_packet"), "response"))
			if complete && why == "" && utf8.Valid(raw) {
				o.Response = string(raw)
			}
		}
	}
	if o.HTTP == nil && full && utf8.Valid(payload) {
		method, ok := snapshotStratumMethod(payload)
		if ok {
			o.Payload, o.Complete, o.StratumMethod, o.TransactionID = string(payload), true, method, asString(m["transaction_id"])
			response := nestedMap(nestedMap(m, "raw_packet"), "response")
			if o.TransactionID != "" && asString(m["session_id"]) != "" && snapshotSequencePair(packet, response, len(payload)) {
				raw, complete, why := snapshotPayload(response)
				if complete && why == "" && utf8.Valid(raw) {
					o.Response = string(raw)
				}
			}
		}
	}
	if len(o.Payload) > maxSemanticMessageBytes || len(o.Response) > maxSemanticMessageBytes {
		out.Manifest.addIssue(SnapshotInputIssue{Code: "semantic_message_budget_exceeded", Stage: "prepare_semantics", HitID: h.ID, Scope: o.Scope})
		return
	}
	if o.Payload == "" && o.DNS == nil {
		return
	}
	used := len(o.Payload) + len(o.Response) + len(o.Body)
	for _, old := range out.SemanticObservations {
		used += len(old.Payload) + len(old.Response) + len(old.Body)
	}
	if len(out.SemanticObservations) >= maxSemanticObservations || used > maxSemanticObservationBytes {
		out.Manifest.addIssue(SnapshotInputIssue{Code: "semantic_material_budget_exceeded", Stage: "prepare_semantics", HitID: h.ID, Scope: o.Scope})
		return
	}
	out.SemanticObservations = append(out.SemanticObservations, o)
}

func buildSnapshotSemanticRequest(snap EvidenceSnapshot, input SnapshotEvidenceInput, result *evidence.Result, mode evidence.SemanticInputMode) evidence.SemanticRequest {
	r := evidence.SemanticRequest{EventID: snap.EventID, SnapshotVersion: snap.Version, InputMode: mode, Subjects: []evidence.SemanticSubject{}, Slots: prioritizedSemanticSlots()}
	if result == nil {
		return r
	}
	byScope := map[evidence.Scope]evidence.Input{}
	for _, i := range append(append([]evidence.Input(nil), input.Request.Inputs...), input.Request.AssetInputs...) {
		byScope[i.Scope] = i
	}
	factsFor := func(scope evidence.Scope, w evidence.AnalysisWindow) []evidence.Finding {
		fs := []evidence.Finding{}
		for _, f := range result.Findings {
			if f.Scope == scope && f.Window != nil && f.Window.Start.Equal(w.Start) && f.Window.End.Equal(w.End) {
				fs = append(fs, f)
			}
		}
		return fs
	}
	newSubject := func(id string, i evidence.Input) evidence.SemanticSubject {
		return evidence.SemanticSubject{ID: id, PropositionID: id, Scope: i.Scope, Window: *i.Window, Facts: factsFor(i.Scope, *i.Window)}
	}
	material := func(s *evidence.SemanticSubject, kind, text, path string, p evidence.Provenance, complete bool) evidence.SemanticMaterial {
		p.Complete = complete
		return evidence.SemanticMaterial{ID: s.ID + ":" + kind, Kind: kind, Scope: s.Scope, Window: s.Window, SnapshotVersion: snap.Version, Text: text, FieldPath: path, Provenance: p, Redacted: false, Truncated: !complete}
	}
	// Every actual scope has a review subject even when no payload is readable.
	for _, i := range append(append([]evidence.Input(nil), input.Request.Inputs...), input.Request.AssetInputs...) {
		if i.Window == nil {
			continue
		}
		s := newSubject("scope:"+digest(i.Scope), i)
		refs := []string{}
		for _, h := range input.Request.Hits {
			if h.Scope == i.Scope || i.Scope.EndpointID == "asset://"+h.Scope.AssetID && h.Scope.AssetID == i.Scope.AssetID && h.Scope.DeviceID == i.Scope.DeviceID {
				refs = append(refs, h.ID)
			}
		}
		p := evidence.Provenance{Verified: true, Complete: input.Manifest.Coverage == "complete", Version: fmt.Sprintf("%s:%d", snap.EventID, snap.Version), SourceIDs: refs}
		gaps := []string{}
		for _, f := range s.Facts {
			if f.Status == evidence.Missing {
				gaps = append(gaps, string(f.FactID)+":"+string(f.ReasonCode))
			}
		}
		if len(gaps) == 0 {
			gaps = append(gaps, "仅覆盖已保存告警命中，未证明攻击成功；不存在事实缺项也不代表全部网络可见")
		}
		s.Materials = []evidence.SemanticMaterial{material(&s, "visibility", fmt.Sprintf("保存命中%d条，绑定%d条，覆盖=%s；这是告警命中快照，不代表全部通信", input.Manifest.LoadedHits, input.Manifest.BoundHits, input.Manifest.Coverage), "snapshot.input_manifest", p, p.Complete), material(&s, "gaps", strings.Join(gaps, ";"), "facts.reason_code", p, true)}
		addSemanticSupplementalMaterials(&s, i, snap.EventID, material)
		r.Subjects = append(r.Subjects, s)
	}
	for _, o := range input.SemanticObservations {
		i, ok := byScope[o.Scope]
		if !ok || i.Window == nil {
			continue
		}
		s := newSubject("operation:"+o.HitID, i)
		p := evidence.Provenance{Verified: true, Complete: o.Complete, Version: fmt.Sprintf("%s:%d", snap.EventID, snap.Version), SourceIDs: []string{o.HitID}}
		if o.DNS != nil {
			d := material(&s, "domain", o.DNS.Domain, "dns.domain", p, o.Complete)
			lexText := "已保存域名字段；词形相似仅供解释，不证明DGA或恶意归属"
			if !o.Complete {
				lexText += "；DNS完整报文未核验"
			}
			lex := material(&s, "lexical_context", lexText, "dns.question", p, o.Complete)
			s.Materials = append(s.Materials, d, lex)
			addSemanticDecodeMaterials(&s, strings.Split(o.DNS.Domain, ".")[0], []string{d.ID}, material, p)
		}
		if o.HTTP != nil && o.Payload != "" {
			h := o.HTTP
			tx := h.TransactionID
			// A single saved request has a stable local identity even without a
			// probe transaction ID. This cannot establish a cross-message join.
			if tx == "" {
				tx = "hit:" + o.HitID
			}
			request := material(&s, "protocol_request", o.Payload, "raw_packet.request.payload", p, o.Complete)
			request.TransactionID, request.Direction, request.Method, request.Protocol, request.Destination = tx, o.Direction, h.Method, "http", h.URL
			for field := range h.Fields {
				request.FieldNames = append(request.FieldNames, field)
			}
			sort.Strings(request.FieldNames)
			s.Materials = append(s.Materials, request)
			if o.Direction != "" {
				d := material(&s, "direction", o.Direction, "flow.src_ip/dst_ip", p, true)
				d.TransactionID, d.Direction = tx, o.Direction
				s.Materials = append(s.Materials, d)
			}
			if h.UserAgent != "" {
				s.Materials = append(s.Materials, material(&s, "ua", h.UserAgent, "http.user_agent", p, true))
			}
			if strings.EqualFold(h.Method, "POST") && evidence.HasCredentialFields(h.Fields) {
				fields := material(&s, "credential_fields", strings.Join(request.FieldNames, ","), "http.fields.names", p, o.Complete)
				fields.TransactionID, fields.Method, fields.Destination, fields.FieldNames = tx, h.Method, h.URL, request.FieldNames
				s.Materials = append(s.Materials, fields)
			}
			if h.BodyLength != nil && o.Complete {
				volume := material(&s, "volume", fmt.Sprintf("完整HTTP请求体%d字节", *h.BodyLength), "http.body_length", p, true)
				volume.TransactionID, volume.Bytes = tx, h.BodyLength
				s.Materials = append(s.Materials, volume)
			}
			if o.Body != "" {
				body := material(&s, "parsed_payload", o.Body, "http.body", p, o.Complete)
				body.TransactionID = tx
				s.Materials = append(s.Materials, body)
				addSemanticDecodeMaterials(&s, o.Body, []string{request.ID}, material, p)
			}
			if h.ResponseVerified && o.Response != "" && o.Direction != "" && h.TransactionID != "" {
				response := material(&s, "protocol_response", o.Response, "raw_packet.response.payload", p, true)
				response.TransactionID = tx
				response.Direction = "inbound"
				if o.Direction == "inbound" {
					response.Direction = "outbound"
				}
				pair := material(&s, "pair", "程序已核验同事务HTTP请求应答及TCP序列对应；不证明业务操作成功", "http.response_verified/tcp_seq/tcp_ack", p, true)
				pair.TransactionID, pair.RelatedIDs = tx, []string{request.ID, response.ID}
				s.Materials = append(s.Materials, response, pair)
				if parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(o.Response)), nil); err == nil {
					body, readErr := io.ReadAll(io.LimitReader(parsed.Body, maxSemanticMessageBytes))
					parsed.Body.Close()
					if readErr == nil && strings.Contains(strings.ToLower(parsed.Header.Get("Content-Type")), "text/html") && utf8.Valid(body) {
						s.Materials = append(s.Materials, material(&s, "page", string(body), "http.response.body", p, true))
					}
				}
			}
			if parsed, err := http.NewRequest(h.Method, h.URL, nil); err == nil {
				s.Materials = append(s.Materials, material(&s, "host", parsed.URL.Hostname(), "http.url.host", p, true))
			}
			addSemanticSupplementalMaterials(&s, i, snap.EventID, material)
		}
		if o.StratumMethod != "" {
			tx := o.TransactionID
			if tx == "" {
				tx = "hit:" + o.HitID
			}
			request := material(&s, "stratum_request", o.Payload, "raw_packet.request.payload", p, true)
			request.TransactionID, request.Direction, request.Method, request.Protocol, request.FieldNames = tx, o.Direction, o.StratumMethod, "stratum", []string{"params"}
			s.Materials = append(s.Materials, request)
			if o.Response != "" && o.Direction != "" {
				response := material(&s, "stratum_response", o.Response, "raw_packet.response.payload", p, true)
				response.TransactionID, response.Direction = tx, "inbound"
				if o.Direction == "inbound" {
					response.Direction = "outbound"
				}
				pair := material(&s, "pair", "程序核验TCP序列及事务标识，JSON请求响应ID由语义前提校验", "flow.tcp_seq/tcp_ack", p, true)
				pair.TransactionID, pair.RelatedIDs = tx, []string{request.ID, response.ID}
				s.Materials = append(s.Materials, response, pair)
			}
		}
		r.Subjects = append(r.Subjects, s)
	}
	for _, g := range input.Request.Groups {
		if !trustedInputProvenance(g.Provenance) {
			continue
		}
		scope := evidence.Scope{GroupID: g.ID}
		s := evidence.SemanticSubject{ID: "group:" + g.ID, PropositionID: "group:" + g.ID, Scope: scope, Window: g.Window, Facts: factsFor(scope, g.Window)}
		for _, member := range g.Members {
			if !member.MembershipVerified {
				continue
			}
			text := fmt.Sprintf("资产=%s；核验角色=%s；保存关联命中%d条", member.AssetID, member.Role, len(member.HitIDs))
			m := material(&s, "group_member", text, "group.members", g.Provenance, true)
			m.ID += ":" + member.AssetID
			m.AssetID, m.Role = member.AssetID, member.Role
			s.Materials = append(s.Materials, m)
		}
		r.Subjects = append(r.Subjects, s)
	}
	return r
}

type semanticMaterialFactory func(*evidence.SemanticSubject, string, string, string, evidence.Provenance, bool) evidence.SemanticMaterial

func addSemanticSupplementalMaterials(s *evidence.SemanticSubject, i evidence.Input, currentEventID string, makeMaterial semanticMaterialFactory) {
	if i.HTTP != nil && i.HTTP.BrandsVerified && len(i.HTTP.Brands) > 0 {
		raw, _ := json.Marshal(i.HTTP.Brands)
		s.Materials = append(s.Materials, makeMaterial(s, "brand_authorization", string(raw), "http.brands", i.HTTP.Provenance, true))
	}
	if i.Authorizations != nil && trustedInputProvenance(i.Authorizations.Provenance) {
		matched := []evidence.AuthorizationRecord{}
		roles := map[string]bool{}
		for _, a := range i.Authorizations.Records {
			if a.AssetID == s.Scope.AssetID && !a.Start.After(s.Window.Start) && !a.End.Before(s.Window.End) && (a.Endpoint == "" || a.Endpoint == s.Scope.EndpointID) {
				matched = append(matched, a)
				if a.Role != "" {
					roles[a.Role] = true
				}
			}
		}
		if len(matched) > 0 {
			raw, _ := json.Marshal(matched)
			s.Materials = append(s.Materials, makeMaterial(s, "task_context", string(raw), "authorizations.records", i.Authorizations.Provenance, true))
			if len(roles) == 1 {
				for role := range roles {
					m := makeMaterial(s, "asset_role", role, "authorizations.role", i.Authorizations.Provenance, true)
					m.Role = role
					s.Materials = append(s.Materials, m)
				}
			}
		}
	}
	if h := i.History; h != nil && trustedInputProvenance(h.Provenance) {
		count := 0
		for _, e := range h.Events {
			if count >= 5 {
				break
			}
			if e.ID == "" || e.ID == currentEventID || e.AssetID != s.Scope.AssetID || e.Endpoint != "" && e.Endpoint != s.Scope.EndpointID || e.AdjudicationID == "" || (e.AdjudicationSource != "human" && e.AdjudicationSource != "host_evidence" && e.AdjudicationSource != "authoritative_external") || !e.Time.Before(s.Window.Start) {
				continue
			}
			raw, _ := json.Marshal(e)
			m := makeMaterial(s, "history", string(raw), "history.events", h.Provenance, true)
			m.ID += ":" + e.ID
			m.EventID, m.AdjudicationID, m.AdjudicationSource, m.FalsePositive = e.ID, e.AdjudicationID, e.AdjudicationSource, e.Adjudication == "false_positive"
			s.Materials = append(s.Materials, m)
			count++
		}
		if count > 0 {
			s.Materials = append(s.Materials, makeMaterial(s, "current_pattern", fmt.Sprintf("范围=%s；IOC=%s；历史独立裁决用于人工参考，不认定当前战役归属", s.Scope.EndpointID, h.IOC), "history.current", h.Provenance, true))
		}
	}
}

func snapshotStratumMethod(payload []byte) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var obj map[string]json.RawMessage
	if decoder.Decode(&obj) != nil {
		return "", false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return "", false
	}
	var method string
	var params []json.RawMessage
	if json.Unmarshal(obj["method"], &method) != nil || !strings.HasPrefix(method, "mining.") || json.Unmarshal(obj["params"], &params) != nil || params == nil {
		return "", false
	}
	return method, true
}

func snapshotSequencePair(request, response map[string]any, payloadBytes int) bool {
	seq, sok := strictUint(request["tcp_seq"])
	ack, aok := strictUint(response["tcp_ack"])
	reqAck, rok := strictUint(request["tcp_ack"])
	respSeq, pok := strictUint(response["tcp_seq"])
	return sok && aok && rok && pok && seq <= 0xffffffff && ack <= 0xffffffff && reqAck <= 0xffffffff && respSeq <= 0xffffffff && ((seq+uint64(payloadBytes))&0xffffffff) == ack && reqAck == respSeq
}

func addSemanticDecodeMaterials(s *evidence.SemanticSubject, text string, linked []string, makeMaterial semanticMaterialFactory, p evidence.Provenance) {
	// Only decode an entire explicitly delimited value/label; no substring
	// fishing, decompression, execution or guessing multiple layers.
	candidate := strings.TrimSpace(text)
	if len(candidate) < 12 || len(candidate) > 4096 {
		return
	}
	for _, encoding := range []string{"hex", "base64", "base64url"} {
		var decoded []byte
		var err error
		switch encoding {
		case "hex":
			decoded, err = hex.DecodeString(candidate)
		case "base64":
			decoded, err = base64.StdEncoding.DecodeString(candidate)
		case "base64url":
			decoded, err = base64.RawURLEncoding.DecodeString(candidate)
		}
		if err != nil || len(decoded) == 0 || !utf8.Valid(decoded) || strings.IndexFunc(string(decoded), func(r rune) bool { return r < 32 && r != '\n' && r != '\r' && r != '\t' }) >= 0 {
			continue
		}
		encoded := makeMaterial(s, "encoded_payload", candidate, "payload.encoded_value", p, p.Complete)
		plain := makeMaterial(s, "decoded_payload", string(decoded), "payload.decoded_value", p, p.Complete)
		proof := makeMaterial(s, "decode", "程序验证单层"+encoding+"解码；解码成功不证明恶意", "payload.decode_steps", p, p.Complete)
		proof.DecodeSteps = []evidence.SemanticDecodeStep{{Encoding: encoding, InputID: encoded.ID, OutputID: plain.ID}}
		context := makeMaterial(s, "operation_context", "解码结果来自当前保存的请求/域名", "payload.operation", p, p.Complete)
		context.RelatedIDs = []string{plain.ID}
		for n := range s.Materials {
			for _, id := range linked {
				if s.Materials[n].ID == id {
					s.Materials[n].RelatedIDs = append(s.Materials[n].RelatedIDs, encoded.ID, plain.ID)
				}
			}
		}
		s.Materials = append(s.Materials, encoded, plain, proof, context)
		return
	}
}

func prioritizedSemanticSlots() []evidence.SlotKey {
	// Action and paired-message explanations precede lexical/visibility tasks.
	order := []string{"S06", "S09", "S10", "S02", "S01", "S11", "S13", "S04", "S05", "SC03", "BT-S01", "S03", "S12", "S07", "S08", "SC01", "S14", "SC02", "R06", "R07", "S15"}
	out := []evidence.SlotKey{}
	for _, id := range order {
		for _, d := range evidence.SemanticDefinitions() {
			if d.Key.ID == id {
				out = append(out, d.Key)
			}
		}
	}
	return out
}
