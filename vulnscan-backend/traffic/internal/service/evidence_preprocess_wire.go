package service

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/dns/dnsmessage"
	"vulnscan-backend/evidence"
)

// Per-hit lifetime only. Never stored in a raw hit, shared globally or promoted
// across versions. Failed parses are cached too, preserving identical diagnostics.
type snapshotParseContext struct {
	frames       map[string]snapshotParsedFrame
	decoded      gopacket.Packet
	decodedRaw   string
	dns          *dnsmessage.Message
	dnsData      string
	dnsErr       error
	frameDecodes int64
	httpParses   int64
	dnsParses    int64
}

func snapshotDecodeFrame(m map[string]any, raw string) (gopacket.Packet, error) {
	c := snapshotParsing(m)
	if c != nil && c.decoded != nil && c.decodedRaw == raw {
		return c.decoded, nil
	}
	if raw == "" || len(raw) > 2*maxEvidenceMessageBytes {
		return nil, fmt.Errorf("frame_missing_or_oversized")
	}
	frame, err := decodeSnapshotPayloadHex(raw)
	if err != nil {
		return nil, err
	}
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if c != nil {
		c.frameDecodes++
		c.decodedRaw, c.decoded = raw, p
	}
	return p, nil
}

func snapshotDecodeDNS(m map[string]any, data []byte) (dnsmessage.Message, error) {
	c := snapshotParsing(m)
	if c != nil && c.dns != nil && c.dnsData == string(data) {
		return *c.dns, c.dnsErr
	}
	var msg dnsmessage.Message
	err := msg.Unpack(data)
	if c != nil {
		c.dnsParses++
		c.dns, c.dnsData, c.dnsErr = &msg, string(data), err
	}
	return msg, err
}

type snapshotParsedFrame struct {
	packet  map[string]any
	problem string
}

const snapshotParseContextKey = "_evidence_pipeline_parse_context"

func snapshotParsing(m map[string]any) *snapshotParseContext {
	c, _ := m[snapshotParseContextKey].(*snapshotParseContext)
	return c
}

func snapshotFramePayload(packet, m map[string]any, input *evidence.Input) (map[string]any, string) {
	c := snapshotParsing(m)
	if c == nil {
		return computeSnapshotFramePayload(packet, m, input)
	}
	key := fmt.Sprintf("%p", packet)
	if result, ok := c.frames[key]; ok {
		return result.packet, result.problem
	}
	parsed, problem := computeSnapshotFramePayload(packet, m, input)
	if c.frames == nil {
		c.frames = map[string]snapshotParsedFrame{}
	}
	c.frames[key] = snapshotParsedFrame{parsed, problem}
	return parsed, problem
}
