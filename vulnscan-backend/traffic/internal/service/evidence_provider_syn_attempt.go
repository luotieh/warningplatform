package service

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"vulnscan-backend/evidence"
	"vulnscan-backend/traffic/internal/store"
)

// The top-level packet is the triggering observation. Request/exchange context
// can belong to another packet and must never supply an initial SYN attempt.
// Asset ownership was resolved by snapshotScope before this entry point.
func enrichProviderSYNAttempt(input *evidence.Input, h store.Hit, m map[string]any, manifest *SnapshotEvidenceManifest) {
	if input == nil || input.Network == nil {
		return
	}
	packet := nestedMap(m, "raw_packet")
	raw := asString(packet["packet_hex"])
	if raw == "" {
		return
	}
	frame, err := snapshotDecodeFrame(m, raw)
	if err != nil || frame.ErrorLayer() != nil || frame.Metadata().Truncated {
		return // the shared frame parser already records invalid-frame diagnostics
	}
	tcp, ok := frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || !tcp.SYN || tcp.ACK {
		return
	}
	reject := func(code string) {
		if manifest != nil {
			manifest.addIssue(SnapshotInputIssue{Code: code, Stage: "syn_attempt", Field: "raw_packet.packet_hex/capture_time", HitID: h.ID, Scope: input.Scope})
		}
	}
	for _, key := range []string{"captured_length", "wire_length"} {
		if packet[key] != nil {
			n, valid := strictUint(packet[key])
			if !valid || n != uint64(len(frame.Data())) {
				reject("syn_attempt_frame_length_conflict")
				return
			}
		}
	}
	if tcp.RST || tcp.FIN || tcp.DataOffset < 5 || len(tcp.Contents) != int(tcp.DataOffset)*4 {
		reject("syn_attempt_tcp_header_invalid")
		return
	}
	if truncated, known := packet["capture_truncated"].(bool); known && truncated {
		reject("syn_attempt_capture_truncated")
		return
	}
	src, dst := "", ""
	complete := false
	if layer := frame.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		src, dst = ip.SrcIP.String(), ip.DstIP.String()
		complete = ip.Protocol == layers.IPProtocolTCP && ip.Length >= uint16(ip.IHL)*4 && len(ip.Contents)+len(ip.Payload) >= int(ip.Length) && ip.FragOffset == 0 && ip.Flags&layers.IPv4MoreFragments == 0
	}
	if layer := frame.Layer(layers.LayerTypeIPv6); layer != nil {
		ip := layer.(*layers.IPv6)
		src, dst = ip.SrcIP.String(), ip.DstIP.String()
		// Extension/tunnel reconstruction is outside this initial-frame subset.
		complete = ip.NextHeader == layers.IPProtocolTCP && ip.Length > 0 && len(ip.Payload) >= int(ip.Length) && frame.Layer(layers.LayerTypeIPv6Fragment) == nil
	}
	if !complete {
		reject("syn_attempt_datagram_incomplete_or_fragmented")
		return
	}
	sp, spOK := strictUint(m["src_port"])
	dp, dpOK := strictUint(m["dst_port"])
	if !strings.EqualFold(firstNonEmpty(asString(m["protocol"]), asString(m["proto"])), "tcp") ||
		!net.ParseIP(src).Equal(net.ParseIP(asString(m["src_ip"]))) || !net.ParseIP(dst).Equal(net.ParseIP(asString(m["dst_ip"]))) ||
		!spOK || !dpOK || sp == 0 || dp == 0 || sp != uint64(tcp.SrcPort) || dp != uint64(tcp.DstPort) {
		reject("syn_attempt_flow_tuple_conflict")
		return
	}
	source, sourceErr := netip.ParseAddr(src)
	target, targetErr := netip.ParseAddr(dst)
	if sourceErr != nil || targetErr != nil || source.IsUnspecified() || target.IsUnspecified() || source.IsMulticast() || target.IsMulticast() {
		reject("syn_attempt_address_invalid")
		return
	}
	src, dst = source.Unmap().String(), target.Unmap().String()
	endpoint := "tcp://" + net.JoinHostPort(dst, strconv.FormatUint(dp, 10))
	// The registered local asset must be the SYN source. Inbound SYNs cannot
	// be attributed to its outbound port sequence merely by reversing a tuple.
	if input.Scope.AssetID == "" || input.Scope.DeviceID == "" || input.Scope.GroupID != "" ||
		asString(m["device_id"]) != input.Scope.DeviceID || input.Scope.EndpointID != endpoint {
		reject("syn_attempt_asset_direction_binding_invalid")
		return
	}
	at, timeOK := providerExchangePacketTime(packet)
	if packet["capture_time_usec"] != nil {
		usec, valid := strictUint(packet["capture_time_usec"])
		if !valid || usec == 0 || usec > 253402300799999999 || !time.UnixMicro(int64(usec)).Equal(at) {
			timeOK = false
		}
	}
	if !timeOK || h.ID == "" || h.OccurredAt.IsZero() || !at.Equal(h.OccurredAt) || input.Window == nil ||
		!input.Window.Start.Before(input.Window.End) || at.Before(input.Window.Start) || !at.Before(input.Window.End) {
		reject("syn_attempt_capture_time_binding_invalid")
		return
	}
	sid := asString(m["session_id"])
	if strings.TrimSpace(sid) == "" {
		reject("syn_attempt_session_identity_missing")
		return
	}
	index := -1
	for i, row := range input.Network.Connections {
		if row.SourceID == h.ID {
			if index >= 0 {
				reject("syn_attempt_connection_identity_ambiguous")
				return
			}
			index = i
		}
	}
	if index < 0 {
		reject("syn_attempt_connection_binding_missing")
		return
	}
	row := &input.Network.Connections[index]
	if row.AssetID != input.Scope.AssetID || row.Destination != dst || row.Port != uint16(dp) || !row.Time.Equal(at) || row.SessionID != sid || row.OutcomeVerified {
		reject("syn_attempt_connection_binding_invalid")
		return
	}
	row.Transport, row.TCPState = "tcp", "SYN"
	row.SYNAttemptVerification = &evidence.TCPSYNAttemptVerification{
		Version: evidence.TCPSYNAttemptVerificationVersion, Scope: input.Scope,
		SourceID: h.ID, SourceOccurredAt: h.OccurredAt, SourceAddress: src, SourcePort: uint16(sp),
		Destination: dst, DestinationPort: uint16(dp), Sequence: tcp.Seq, SessionID: sid,
	}
}
