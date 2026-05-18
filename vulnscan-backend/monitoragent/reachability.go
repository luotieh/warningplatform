package monitoragent

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	reachabilityTimeout   = 5 * time.Second
	reachabilityDialTime  = 3 * time.Second
	reachabilityBodyLimit = 4096
)

// ProbeHTTPReachable 轻量可用性探测：优先 HEAD，必要时短 GET，不拉取整页内容。
func ProbeHTTPReachable(ctx context.Context, rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, reachabilityTimeout)
	defer cancel()

	client := &http.Client{
		Timeout: reachabilityTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: reachabilityDialTime,
			DialContext: (&net.Dialer{
				Timeout:   reachabilityDialTime,
				KeepAlive: 0,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	defer client.CloseIdleConnections()

	if ok, done := tryReachabilityRequest(ctx, client, http.MethodHead, rawURL); done {
		return ok
	}
	ok, _ := tryReachabilityRequest(ctx, client, http.MethodGet, rawURL)
	return ok
}

func tryReachabilityRequest(ctx context.Context, client *http.Client, method, rawURL string) (bool, bool) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return false, true
	}
	req.Header.Set("User-Agent", defaultUA)
	resp, err := client.Do(req)
	if err != nil {
		return false, method == http.MethodGet
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, reachabilityBodyLimit)
	if resp.StatusCode == 0 {
		return false, method == http.MethodGet
	}
	// 405/501 等不支持 HEAD 时回退 GET
	if method == http.MethodHead && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		return false, false
	}
	return resp.StatusCode > 0 && resp.StatusCode < 500, true
}
