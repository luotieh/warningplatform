package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

// One entry per immutable hit. Kept with the fact cache so cache hits retain
// metadata from the entire membership, rather than representative packets.
type ReportMaterialObservation struct {
	PhysicalPacketID string          `json:"physical_packet_id,omitempty"`
	Direction        string          `json:"direction"`
	HitID            string          `json:"hit_id"`
	Time             time.Time       `json:"time"`
	Scope            evidence.Scope  `json:"scope"`
	Source           string          `json:"source"`
	Destination      string          `json:"destination"`
	Protocol         string          `json:"protocol"`
	Application      json.RawMessage `json:"application,omitempty"`
}

func reportMaterialObservation(h store.Hit, m map[string]any, scope evidence.Scope) ReportMaterialObservation {
	o := ReportMaterialObservation{HitID: h.ID, Time: h.OccurredAt, Scope: scope, Source: net.JoinHostPort(asString(m["src_ip"]), fmt.Sprint(m["src_port"])), Destination: net.JoinHostPort(asString(m["dst_ip"]), fmt.Sprint(m["dst_port"])), Protocol: asString(m["protocol"])}
	endpoint := strings.TrimPrefix(strings.TrimPrefix(scope.EndpointID, "tcp://"), "udp://")
	remote, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		if remote == asString(m["src_ip"]) {
			o.Direction = "inbound"
		} else if remote == asString(m["dst_ip"]) {
			o.Direction = "outbound"
		}
	}
	packet := nestedMap(m, "raw_packet")
	if raw := asString(packet["packet_hex"]); raw != "" && asString(packet["capture_time"]) != "" {
		sum := sha256.Sum256([]byte(fmt.Sprint(packet["capture_time_usec"]) + ":" + asString(packet["capture_time"]) + ":" + raw))
		o.PhysicalPacketID = hex.EncodeToString(sum[:])
	}
	app := nestedMap(m, "app")
	fields := map[string]any{}
	for _, k := range []string{"sni", "tls_sni", "dns_query", "dns_answers", "dns_qtype", "host", "url", "method", "user_agent", "ssh_banner"} {
		if v, ok := app[k]; ok {
			fields[k] = v
		}
	}
	if len(fields) > 0 {
		o.Application, _ = json.Marshal(fields)
	}
	return o
}

// Derive completeness of this single IPv4/IPv6 datagram only. This says
// nothing about completeness of a TCP stream or the total traffic window.
func reportVerifyDatagram(m map[string]any) {
	packet := nestedMap(m, "raw_packet")
	if _, known := packet["capture_truncated"].(bool); known {
		return
	}
	raw, err := hex.DecodeString(asString(packet["packet_hex"]))
	if err != nil || len(raw) == 0 {
		return
	}
	p := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	complete := false
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		complete = len(ip.Contents)+len(ip.Payload) >= int(ip.Length) && ip.FragOffset == 0 && ip.Flags&layers.IPv4MoreFragments == 0
	}
	if l := p.Layer(layers.LayerTypeIPv6); l != nil {
		ip := l.(*layers.IPv6)
		complete = len(ip.Payload) >= int(ip.Length) && p.Layer(layers.LayerTypeIPv6Fragment) == nil
	}
	if complete && p.ErrorLayer() == nil {
		packet["capture_truncated"] = false
		packet["report_quality_derivation"] = "validated_datagram_length; stream completeness not inferred"
		// Read the actual transport payload, including DNS bytes. A saved empty
		// application preview is not proof of a payload-free packet.
		if transport := p.TransportLayer(); transport != nil {
			packet["payload_hex"] = hex.EncodeToString(transport.LayerPayload())
		}
	}
}

func reportMaterialEvidence(rows []ReportMaterialObservation) []ReportEvidence {
	if len(rows) == 0 {
		return nil
	}
	groups := map[string][]ReportMaterialObservation{}
	for _, r := range rows {
		key := r.Scope.AssetID + " / " + r.Scope.DeviceID
		groups[key] = append(groups[key], r)
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []ReportEvidence{}
	for _, k := range keys {
		rs := groups[k]
		sort.Slice(rs, func(i, j int) bool { return rs[i].Time.Before(rs[j].Time) })
		ports := map[string]int{}
		remotePorts := map[string]int{}
		remoteEndpoints := map[string]bool{}
		protocolPorts := map[string]bool{}
		localAddresses := map[string]bool{}
		physical := map[string]bool{}
		unknownPhysical := 0
		apps := map[string]bool{}
		refs := []string{}
		for _, r := range rs {
			ports[r.Source+" → "+r.Destination+" / "+r.Protocol]++
			remotePorts[r.Direction+" "+r.Scope.EndpointID]++
			remoteEndpoints[r.Scope.EndpointID] = true
			endpoint := strings.TrimPrefix(strings.TrimPrefix(r.Scope.EndpointID, "tcp://"), "udp://")
			if _, port, err := net.SplitHostPort(endpoint); err == nil {
				protocolPorts[r.Protocol+":"+port] = true
			}
			local := r.Source
			if r.Direction == "inbound" {
				local = r.Destination
			}
			if ip, _, err := net.SplitHostPort(local); err == nil {
				localAddresses[ip] = true
			}
			if r.PhysicalPacketID != "" {
				physical[r.PhysicalPacketID] = true
			} else {
				unknownPhysical++
			}
			if len(r.Application) > 0 {
				apps[string(r.Application)] = true
			}
			refs = append(refs, r.HitID)
		}
		pk := []string{}
		for p := range ports {
			pk = append(pk, p)
		}
		sort.Strings(pk)
		parts := []string{}
		for _, p := range pk {
			parts = append(parts, fmt.Sprintf("%s：%d条命中", p, ports[p]))
		}
		ak := []string{}
		for a := range apps {
			ak = append(ak, a)
		}
		sort.Strings(ak)
		remoteKeys := []string{}
		for p := range remotePorts {
			remoteKeys = append(remoteKeys, p)
		}
		sort.Strings(remoteKeys)
		remoteParts := []string{}
		for _, p := range remoteKeys {
			remoteParts = append(remoteParts, fmt.Sprintf("%s：%d条", p, remotePorts[p]))
		}
		first, last := rs[0].Time, rs[len(rs)-1].Time
		locals := []string{}
		for ip := range localAddresses {
			locals = append(locals, ip)
		}
		sort.Strings(locals)
		result := fmt.Sprintf("资产地址=%s；资产/设备=%s；已保存命中%d条；已保存去重物理报文%d份，无法建立物理身份%d条；涉及%d个远端端点、%d种协议端口；时间UTC=%s 至 %s；跨度=%.6f秒；远端与方向完整分布：%s", strings.Join(locals, ","), k, len(rs), len(physical), unknownPhysical, len(remoteEndpoints), len(protocolPorts), first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano), last.Sub(first).Seconds(), strings.Join(remoteParts, "；"))
		out = append(out, ReportEvidence{Kind: "observation", Name: "全量命中通联与时间分布", Status: "observed", Result: result, Source: "固定快照全部绑定命中的时间与五元组", SourceIDs: refs, Scope: rs[0].Scope, Family: "saved_activity:" + k, Window: &evidence.Window{Start: first, End: last, Convention: "observed_first_last_inclusive"}})
		if len(ak) > 0 {
			out = append(out, ReportEvidence{Kind: "observation", Name: "实际应用层字段", Status: "observed", Result: strings.Join(ak, "；"), Source: "全量命中保存的应用字段；不继承情报关联域名", SourceIDs: refs, Scope: rs[0].Scope, Family: "application:" + k})
		}
	}
	return out
}

func reportDNSConnectionEvidence(rows []ReportMaterialObservation, h *ReportHistory) []ReportEvidence {
	if h == nil {
		return nil
	}
	out := []ReportEvidence{}
	seen := map[string]bool{}
	for _, current := range rows {
		if current.Protocol != "tcp" {
			continue
		}
		endpoint := strings.TrimPrefix(strings.TrimPrefix(current.Scope.EndpointID, "tcp://"), "udp://")
		remote, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			continue
		}
		var app map[string]any
		_ = json.Unmarshal(current.Application, &app)
		sni := firstNonEmpty(asString(app["tls_sni"]), asString(app["sni"]))
		if sni == "" {
			continue
		}
		for _, prior := range h.Rows {
			if prior.DeviceID != current.Scope.DeviceID || !slices.Contains(prior.AllAssetIDs, current.Scope.AssetID) || !prior.First.Equal(prior.Last) {
				continue
			}
			domain := asString(prior.Application["dns_query"])
			if !strings.EqualFold(domain, sni) {
				continue
			}
			answers, ok := prior.Application["dns_answers"].([]any)
			if !ok {
				continue
			}
			matched := false
			for _, answer := range answers {
				if asString(answer) == remote {
					matched = true
				}
			}
			delta := current.Time.Sub(prior.Last)
			if !matched || delta < 0 || delta > 5*time.Minute {
				continue
			}
			key := prior.EventID + ":" + current.Scope.EndpointID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ReportEvidence{Kind: "observation", Name: "DNS解析与后续目标连接关联", Status: "observed", Result: fmt.Sprintf("同资产、同设备；历史事件%s保存DNS查询=%s、应答包含%s（UTC %s）；当前命中%s在%.6f秒后连接该IP且SNI=%s。关联为解析→连接，未将情报域名当作实际查询域名。", prior.EventID, domain, remote, prior.Last.Format(time.RFC3339Nano), current.HitID, delta.Seconds(), sni), Source: "平台历史事件应用字段＋当前固定快照五元组及SNI；5分钟精确匹配", SourceIDs: []string{prior.EventID, current.HitID}, Scope: current.Scope, Family: "dns_connection:" + key})
		}
	}
	return out
}
