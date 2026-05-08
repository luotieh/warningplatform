package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Pool struct {
	proxies     []*Proxy
	mu          sync.RWMutex
	checkTicker *time.Ticker
}

func NewPool() *Pool {
	return &Pool{}
}

func (p *Pool) Add(proxies ...Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := range proxies {
		px := proxies[i]
		px.Score = 50
		px.Alive = true
		p.proxies = append(p.proxies, &px)
	}
}

func (p *Pool) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, px := range p.proxies {
		if px.ID == id {
			p.proxies = append(p.proxies[:i], p.proxies[i+1:]...)
			return
		}
	}
}

func (p *Pool) Select(target string) *Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var alive []*Proxy
	for _, px := range p.proxies {
		if !px.Alive {
			continue
		}
		banned := false
		for _, b := range px.BannedFor {
			if b == target {
				banned = true
				break
			}
		}
		if !banned {
			alive = append(alive, px)
		}
	}

	if len(alive) == 0 {
		return nil
	}

	return weightedSelect(alive)
}

func weightedSelect(proxies []*Proxy) *Proxy {
	totalWeight := 0
	for _, px := range proxies {
		totalWeight += px.Score
	}
	if totalWeight <= 0 {
		return proxies[rand.Intn(len(proxies))]
	}

	r := rand.Intn(totalWeight)
	cumulative := 0
	for _, px := range proxies {
		cumulative += px.Score
		if r < cumulative {
			return px
		}
	}

	return proxies[len(proxies)-1]
}

func (p *Pool) ReportSuccess(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, px := range p.proxies {
		if px.ID == id {
			px.UsedCount++
			px.Score = min(100, px.Score+5)
			return
		}
	}
}

func (p *Pool) ReportFailure(id, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, px := range p.proxies {
		if px.ID == id {
			px.FailCount++
			px.Score = max(0, px.Score-10)

			if px.FailCount >= 3 {
				px.Alive = false
			}
			return
		}
	}
}

func (p *Pool) ReportBan(id, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, px := range p.proxies {
		if px.ID == id {
			px.BannedFor = append(px.BannedFor, target)
			px.Score = max(0, px.Score-20)
			return
		}
	}
}

func (p *Pool) StartHealthCheck(ctx context.Context, interval time.Duration) {
	p.checkTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				p.checkTicker.Stop()
				return
			case <-p.checkTicker.C:
				p.healthCheck(ctx)
			}
		}
	}()
}

func (p *Pool) healthCheck(ctx context.Context) {
	p.mu.RLock()
	proxies := make([]*Proxy, len(p.proxies))
	copy(proxies, p.proxies)
	p.mu.RUnlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, px := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(proxy *Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			alive, latency := checkProxy(ctx, proxy)

			p.mu.Lock()
			proxy.Alive = alive
			proxy.Latency = latency
			proxy.LastCheck = time.Now()
			if alive {
				proxy.FailCount = 0
				proxy.Score = min(100, proxy.Score+2)
			} else {
				proxy.Score = max(0, proxy.Score-15)
			}
			p.mu.Unlock()
		}(px)
	}

	wg.Wait()

	aliveCount := 0
	p.mu.RLock()
	for _, px := range p.proxies {
		if px.Alive {
			aliveCount++
		}
	}
	p.mu.RUnlock()

	slog.Info("[*] 代理池健康检查完成",
		"total", len(proxies),
		"alive", aliveCount,
	)
}

func checkProxy(ctx context.Context, px *Proxy) (bool, int) {
	proxyURL := fmt.Sprintf("%s://%s:%d", px.Protocol, px.Host, px.Port)
	if px.Username != "" {
		proxyURL = fmt.Sprintf("%s://%s:%s@%s:%d", px.Protocol, px.Username, px.Password, px.Host, px.Port)
	}

	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return false, 0
	}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(parsedURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/ip", nil)
	if err != nil {
		return false, 0
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()

	latency := int(time.Since(start).Milliseconds())
	return resp.StatusCode == 200, latency
}

func (p *Pool) GetHTTPClient(target string) *http.Client {
	px := p.Select(target)
	if px == nil {
		return http.DefaultClient
	}

	proxyURL := fmt.Sprintf("%s://%s:%d", px.Protocol, px.Host, px.Port)
	if px.Username != "" {
		proxyURL = fmt.Sprintf("%s://%s:%s@%s:%d", px.Protocol, px.Username, px.Password, px.Host, px.Port)
	}

	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return http.DefaultClient
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(parsedURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
		},
	}
}

func (p *Pool) Stats() map[string]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := map[string]int{
		"total": len(p.proxies),
		"alive": 0,
		"dead":  0,
	}

	for _, px := range p.proxies {
		if px.Alive {
			stats["alive"]++
		} else {
			stats["dead"]++
		}
	}
	return stats
}
