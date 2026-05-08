package favicon

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/scan/engine"
)

type FaviconScanner struct {
	client *http.Client
}

func New() *FaviconScanner {
	return &FaviconScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 5,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			},
		},
	}
}

func (m *FaviconScanner) ID() string       { return "favicon" }
func (m *FaviconScanner) Name() string     { return "Favicon Hash" }
func (m *FaviconScanner) Category() string { return "recon" }

var faviconPaths = []string{
	"/favicon.ico",
	"/favicon.png",
	"/apple-touch-icon.png",
	"/static/favicon.ico",
	"/assets/favicon.ico",
}

func (m *FaviconScanner) Run(ctx context.Context, targets []*engine.Target, config map[string]interface{}) (*engine.ModuleResult, error) {
	start := time.Now()
	result := &engine.ModuleResult{ModuleID: m.ID()}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, t := range targets {
		baseURL := buildBaseURL(t)
		if baseURL == "" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target *engine.Target, base string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, path := range faviconPaths {
				select {
				case <-ctx.Done():
					return
				default:
				}

				faviconURL := base + path
				data := m.fetchFavicon(ctx, faviconURL)
				if data == nil || len(data) < 10 {
					continue
				}

				mmh3Hash := mmh3Hash32(standBase64(data))
				shodanQuery := fmt.Sprintf("http.favicon.hash:%d", mmh3Hash)
				fofaQuery := fmt.Sprintf("icon_hash=\"%d\"", mmh3Hash)

				mu.Lock()
				result.Findings = append(result.Findings, &engine.Finding{
					ModuleID:   m.ID(),
					Target:     target,
					Type:       "favicon_hash",
					Title:      fmt.Sprintf("Favicon Hash: %d", mmh3Hash),
					Severity:   "info",
					Confidence: 90,
					Timestamp:  time.Now(),
					Data: map[string]string{
						"hash":         fmt.Sprintf("%d", mmh3Hash),
						"url":          faviconURL,
						"size":         fmt.Sprintf("%d", len(data)),
						"shodan_query": shodanQuery,
						"fofa_query":   fofaQuery,
					},
				})
				mu.Unlock()
				break
			}
		}(t, baseURL)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[+] Favicon Hash完成", "targets", len(targets), "findings", len(result.Findings), "duration", result.Duration)
	return result, nil
}

func (m *FaviconScanner) fetchFavicon(ctx context.Context, rawURL string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil
	}
	return data
}

func standBase64(data []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(data)
	var result strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		result.WriteString(encoded[i:end])
		result.WriteString("\n")
	}
	return []byte(result.String())
}

// mmh3Hash32 implements MurmurHash3 (32-bit) used by Shodan for favicon hashing
func mmh3Hash32(data []byte) int32 {
	var h mmh3Hasher
	h.seed = 0
	h.Write(data)
	return int32(h.Sum32())
}

type mmh3Hasher struct {
	seed uint32
	buf  []byte
	h    uint32
	len  int
}

func (h *mmh3Hasher) Write(p []byte) (n int, err error) {
	h.len += len(p)
	h.buf = append(h.buf, p...)

	for len(h.buf) >= 4 {
		k := uint32(h.buf[0]) | uint32(h.buf[1])<<8 | uint32(h.buf[2])<<16 | uint32(h.buf[3])<<24

		k *= 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k *= 0x1b873593

		h.h ^= k
		h.h = (h.h << 13) | (h.h >> 19)
		h.h = h.h*5 + 0xe6546b64

		h.buf = h.buf[4:]
	}

	return len(p), nil
}

func (h *mmh3Hasher) Sum32() uint32 {
	hh := h.h ^ h.seed

	var k uint32
	switch len(h.buf) {
	case 3:
		k ^= uint32(h.buf[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(h.buf[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(h.buf[0])
		k *= 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k *= 0x1b873593
		hh ^= k
	}

	hh ^= uint32(h.len)

	hh ^= hh >> 16
	hh *= 0x85ebca6b
	hh ^= hh >> 13
	hh *= 0xc2b2ae35
	hh ^= hh >> 16

	return hh
}

// satisfy hash.Hash32 interface for type checking only
var _ hash.Hash32 = (*mmh3Hasher)(nil)

func (h *mmh3Hasher) Sum(b []byte) []byte {
	s := h.Sum32()
	return append(b, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
}
func (h *mmh3Hasher) Reset()         { h.h = 0; h.buf = nil; h.len = 0 }
func (h *mmh3Hasher) Size() int      { return 4 }
func (h *mmh3Hasher) BlockSize() int { return 4 }

func buildBaseURL(t *engine.Target) string {
	if t.URL != "" {
		return strings.TrimRight(t.URL, "/")
	}
	if t.Port <= 0 {
		return ""
	}
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	scheme := "http"
	if t.Port == 443 || t.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, t.Port)
}
