package subdomain

import (
	"encoding/binary"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PipelineDNS massdns 风格的高速 DNS 批量解析器
// 单个 UDP socket + 批量 WriteTo + 异步 ReadFrom
type PipelineDNS struct {
	servers   []serverState
	mu        sync.RWMutex
	pending   map[uint16]*pendingQuery
	results   map[string]*dnsEntry
	rateLimit int
	timeout   time.Duration
	retries   int
	sent      atomic.Int64
	received  atomic.Int64
	errors    atomic.Int64
}

type serverState struct {
	addr    string
	healthy bool
	latency time.Duration
	errors  atomic.Int64
}

type pendingQuery struct {
	domain  string
	sentAt  time.Time
	server  int
	retries int
}

func NewPipelineDNS(servers []string, rateLimit int, timeout time.Duration) *PipelineDNS {
	if len(servers) == 0 {
		servers = []string{
			"8.8.8.8:53", "8.8.4.4:53",
			"1.1.1.1:53", "1.0.0.1:53",
			"223.5.5.5:53", "223.6.6.6:53",
			"114.114.114.114:53", "119.29.29.29:53",
		}
	}
	if rateLimit <= 0 {
		rateLimit = 5000
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var ss []serverState
	for _, s := range servers {
		ss = append(ss, serverState{addr: s, healthy: true})
	}

	return &PipelineDNS{
		servers:   ss,
		pending:   make(map[uint16]*pendingQuery),
		results:   make(map[string]*dnsEntry),
		rateLimit: rateLimit,
		timeout:   timeout,
		retries:   2,
	}
}

// BulkResolve 批量解析域名列表 → 返回 domain → dnsEntry 映射
func (p *PipelineDNS) BulkResolve(domains []string) map[string]*dnsEntry {
	if len(domains) == 0 {
		return p.results
	}

	socketCount := len(p.servers)
	if socketCount > 4 {
		socketCount = 4
	}
	if socketCount < 1 {
		socketCount = 1
	}

	conns := make([]net.PacketConn, 0, socketCount)
	for i := 0; i < socketCount; i++ {
		conn, err := net.ListenPacket("udp4", ":0")
		if err != nil {
			break
		}
		conns = append(conns, conn)
	}

	if len(conns) == 0 {
		slog.Warn("[!] 无法打开UDP socket, 回退到标准解析")
		return nil
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	var recvWg sync.WaitGroup
	for _, conn := range conns {
		recvWg.Add(1)
		go func(c net.PacketConn) {
			defer recvWg.Done()
			p.receiveLoop(c)
		}(conn)
	}

	batchSize := 200
	for i := 0; i < len(domains); i += batchSize {
		end := i + batchSize
		if end > len(domains) {
			end = len(domains)
		}
		batch := domains[i:end]

		for j, domain := range batch {
			txID := p.nextTxID()
			serverIdx := p.pickServer()
			connIdx := j % len(conns)

			pkt := buildDNSQuery(txID, domain)
			dst, err := net.ResolveUDPAddr("udp4", p.servers[serverIdx].addr)
			if err != nil {
				continue
			}

			_, _ = conns[connIdx].WriteTo(pkt, dst)
			p.sent.Add(1)

			p.mu.Lock()
			p.pending[txID] = &pendingQuery{
				domain: domain,
				sentAt: time.Now(),
				server: serverIdx,
			}
			p.mu.Unlock()
		}

		time.Sleep(time.Duration(len(batch)/50+1) * time.Millisecond)
	}

	deadline := time.After(p.timeout + 500*time.Millisecond)
	retryTicker := time.NewTicker(300 * time.Millisecond)
	defer retryTicker.Stop()

	noProgressCount := 0
	lastReceived := p.received.Load()

waitLoop:
	for {
		select {
		case <-deadline:
			break waitLoop
		case <-retryTicker.C:
			for _, conn := range conns {
				p.retryTimedOut(conn)
			}
			p.mu.RLock()
			remaining := len(p.pending)
			p.mu.RUnlock()
			if remaining == 0 {
				break waitLoop
			}

			cur := p.received.Load()
			if cur == lastReceived {
				noProgressCount++
				if noProgressCount >= 10 {
					slog.Debug("[*] DNS Pipeline无新响应，提前结束", "remaining", remaining)
					break waitLoop
				}
			} else {
				noProgressCount = 0
				lastReceived = cur
			}
		}
	}

	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now())
	}
	recvWg.Wait()

	slog.Info("[*] Pipeline DNS完成",
		"sent", p.sent.Load(),
		"received", p.received.Load(),
		"errors", p.errors.Load(),
		"results", len(p.results),
	)

	return p.results
}

func (p *PipelineDNS) receiveLoop(conn net.PacketConn) {
	_ = conn.SetReadDeadline(time.Now().Add(p.timeout + 2*time.Second))
	buf := make([]byte, 4096)

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}

		txID := binary.BigEndian.Uint16(buf[0:2])
		rcode := buf[3] & 0x0F

		p.mu.Lock()
		query, ok := p.pending[txID]
		if ok {
			delete(p.pending, txID)
		}
		p.mu.Unlock()

		if !ok {
			continue
		}

		p.received.Add(1)
		latency := time.Since(query.sentAt)
		if query.server < len(p.servers) {
			p.servers[query.server].latency = latency
		}

		if rcode != 0 {
			p.mu.Lock()
			p.results[query.domain] = &dnsEntry{err: net.UnknownNetworkError("nxdomain")}
			p.mu.Unlock()
			continue
		}

		ips := parseDNSResponse(buf[:n])
		entry := &dnsEntry{ips: ips}
		if len(ips) == 0 {
			entry.err = net.UnknownNetworkError("no_answer")
		}

		p.mu.Lock()
		p.results[query.domain] = entry
		p.mu.Unlock()
	}
}

func (p *PipelineDNS) retryTimedOut(conn net.PacketConn) {
	now := time.Now()
	var toRetry []uint16

	p.mu.Lock()
	for txID, q := range p.pending {
		if now.Sub(q.sentAt) > p.timeout && q.retries < p.retries {
			toRetry = append(toRetry, txID)
		}
	}
	p.mu.Unlock()

	for _, oldTxID := range toRetry {
		p.mu.Lock()
		query, ok := p.pending[oldTxID]
		if !ok {
			p.mu.Unlock()
			continue
		}
		delete(p.pending, oldTxID)

		newTxID := p.nextTxID()
		query.sentAt = now
		query.retries++
		query.server = p.pickServer()
		p.pending[newTxID] = query
		p.mu.Unlock()

		pkt := buildDNSQuery(newTxID, query.domain)
		dst, err := net.ResolveUDPAddr("udp4", p.servers[query.server].addr)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(pkt, dst)
		p.sent.Add(1)
	}
}

func (p *PipelineDNS) pickServer() int {
	var healthy []int
	for i := range p.servers {
		if p.servers[i].healthy {
			healthy = append(healthy, i)
		}
	}
	if len(healthy) == 0 {
		return rand.Intn(len(p.servers))
	}
	return healthy[rand.Intn(len(healthy))]
}

var txIDCounter atomic.Uint32

func (p *PipelineDNS) nextTxID() uint16 {
	return uint16(txIDCounter.Add(1))
}

// --- DNS 包构造/解析 ---

func buildDNSQuery(txID uint16, domain string) []byte {
	var buf []byte

	buf = binary.BigEndian.AppendUint16(buf, txID)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // standard query, recursion desired
	buf = binary.BigEndian.AppendUint16(buf, 1)      // questions
	buf = binary.BigEndian.AppendUint16(buf, 0)      // answers
	buf = binary.BigEndian.AppendUint16(buf, 0)      // authority
	buf = binary.BigEndian.AppendUint16(buf, 0)      // additional

	for _, label := range splitLabels(domain) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label

	buf = binary.BigEndian.AppendUint16(buf, 1) // type A
	buf = binary.BigEndian.AppendUint16(buf, 1) // class IN

	return buf
}

func splitLabels(domain string) []string {
	var labels []string
	current := ""
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				labels = append(labels, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		labels = append(labels, current)
	}
	return labels
}

func parseDNSResponse(data []byte) []string {
	if len(data) < 12 {
		return nil
	}

	anCount := binary.BigEndian.Uint16(data[6:8])
	if anCount == 0 {
		return nil
	}

	offset := 12
	qdCount := binary.BigEndian.Uint16(data[4:6])
	for i := 0; i < int(qdCount); i++ {
		offset = skipName(data, offset)
		if offset < 0 || offset+4 > len(data) {
			return nil
		}
		offset += 4
	}

	var ips []string
	for i := 0; i < int(anCount); i++ {
		offset = skipName(data, offset)
		if offset < 0 || offset+10 > len(data) {
			break
		}

		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		rdlen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdlen) > len(data) {
			break
		}

		if qtype == 1 && rdlen == 4 {
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			ips = append(ips, ip.String())
		}

		offset += int(rdlen)
	}

	return ips
}

func skipName(data []byte, offset int) int {
	if offset >= len(data) {
		return -1
	}
	for {
		if offset >= len(data) {
			return -1
		}
		length := int(data[offset])
		if length == 0 {
			return offset + 1
		}
		if length >= 0xC0 {
			return offset + 2
		}
		offset += 1 + length
	}
}
