package monitorcrawl

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

// Page 爬虫发现的页面。
type Page struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	StatusCode int    `json:"status_code"`
	Depth      int    `json:"depth"`
	Source     string `json:"source"` // http | headless
}

// Options 爬虫参数。
type Options struct {
	StartURL    string
	RequestHost string
	UseHeadless bool
	MaxDepth    int
	MaxPages    int
	SameHost    bool
}

// Result 爬取结果。
type Result struct {
	Pages      []Page  `json:"pages"`
	Crawled    int     `json:"crawled"`
	Errors     int     `json:"errors"`
	DurationMS float64 `json:"duration_ms"`
}

// Crawl 从种子 URL 爬取；UseHeadless 使用 rod 无头浏览器（SPA）。
func Crawl(ctx context.Context, opt Options) *Result {
	start := time.Now()
	if opt.MaxPages <= 0 {
		opt.MaxPages = 50
	}
	if opt.MaxDepth < 0 {
		opt.MaxDepth = 2
	}
	if strings.TrimSpace(opt.StartURL) == "" {
		return &Result{}
	}
	if opt.UseHeadless {
		return crawlHeadless(ctx, opt, start)
	}
	return crawlHTTP(ctx, opt, start)
}

func crawlHTTP(ctx context.Context, opt Options, start time.Time) *Result {
	res := &Result{Pages: make([]Page, 0, opt.MaxPages)}
	base, err := url.Parse(opt.StartURL)
	if err != nil {
		return res
	}
	client := &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	visited := map[string]bool{}
	type item struct {
		u     string
		depth int
	}
	queue := []item{{u: opt.StartURL, depth: 0}}
	visited[normalize(opt.StartURL)] = true

	for len(queue) > 0 && len(res.Pages) < opt.MaxPages {
		select {
		case <-ctx.Done():
			res.DurationMS = float64(time.Since(start).Milliseconds())
			return res
		default:
		}
		cur := queue[0]
		queue = queue[1:]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur.u, nil)
		if err != nil {
			res.Errors++
			continue
		}
		req.Header.Set("User-Agent", defaultUA)
		if h := strings.TrimSpace(opt.RequestHost); h != "" {
			req.Host = h
		}
		resp, err := client.Do(req)
		if err != nil {
			res.Errors++
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		title := ""
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err == nil {
			title = strings.TrimSpace(doc.Find("title").First().Text())
			if cur.depth < opt.MaxDepth {
				doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
					href, ok := s.Attr("href")
					if !ok {
						return
					}
					link := resolveURL(base, href)
					if link == "" || !sameHost(base, link, opt.SameHost) {
						return
					}
					n := normalize(link)
					if visited[n] {
						return
					}
					visited[n] = true
					queue = append(queue, item{u: link, depth: cur.depth + 1})
				})
			}
		}
		res.Pages = append(res.Pages, Page{
			URL:        cur.u,
			Title:      title,
			StatusCode: resp.StatusCode,
			Depth:      cur.depth,
			Source:     "http",
		})
		res.Crawled++
	}
	res.DurationMS = float64(time.Since(start).Milliseconds())
	return res
}

func crawlHeadless(ctx context.Context, opt Options, start time.Time) *Result {
	res := &Result{Pages: make([]Page, 0, opt.MaxPages)}
	base, err := url.Parse(opt.StartURL)
	if err != nil {
		return res
	}

	l := launcher.New().Headless(true)
	controlURL, err := l.Launch()
	if err != nil {
		slog.Warn("monitorcrawl: rod launch failed, fallback http", "error", err)
		return crawlHTTP(ctx, opt, start)
	}
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		slog.Warn("monitorcrawl: rod connect failed", "error", err)
		return crawlHTTP(ctx, opt, start)
	}
	defer browser.Close()

	visited := map[string]bool{}
	type item struct {
		u     string
		depth int
	}
	queue := []item{{u: opt.StartURL, depth: 0}}
	visited[normalize(opt.StartURL)] = true
	var mu sync.Mutex

	for len(queue) > 0 {
		mu.Lock()
		if len(res.Pages) >= opt.MaxPages {
			mu.Unlock()
			break
		}
		mu.Unlock()
		select {
		case <-ctx.Done():
			res.DurationMS = float64(time.Since(start).Milliseconds())
			return res
		default:
		}
		cur := queue[0]
		queue = queue[1:]

		page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			res.Errors++
			continue
		}
		if h := strings.TrimSpace(opt.RequestHost); h != "" {
			_ = proto.NetworkSetExtraHTTPHeaders{Headers: proto.NetworkHeaders{
				"Host": gson.New(h),
			}}.Call(page)
		}
		_ = page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: defaultUA})
		if err := page.Navigate(cur.u); err != nil {
			res.Errors++
			_ = page.Close()
			continue
		}
		_ = page.WaitLoad()
		titleVal, _ := page.Eval(`() => document.title || ''`)
		titleStr := ""
		if titleVal != nil {
			titleStr = strings.TrimSpace(titleVal.Value.String())
		}
		var hrefs []string
		if cur.depth < opt.MaxDepth {
			linkVal, _ := page.Eval(`() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)`)
			if linkVal != nil {
				for _, v := range linkVal.Value.Arr() {
					hrefs = append(hrefs, v.String())
				}
			}
		}
		_ = page.Close()

		mu.Lock()
		res.Pages = append(res.Pages, Page{
			URL:        cur.u,
			Title:      titleStr,
			StatusCode: 200,
			Depth:      cur.depth,
			Source:     "headless",
		})
		res.Crawled++
		mu.Unlock()

		for _, link := range hrefs {
			if !sameHost(base, link, opt.SameHost) {
				continue
			}
			n := normalize(link)
			if visited[n] {
				continue
			}
			visited[n] = true
			queue = append(queue, item{u: link, depth: cur.depth + 1})
		}
	}
	res.DurationMS = float64(time.Since(start).Milliseconds())
	return res
}

const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func sameHost(base *url.URL, raw string, enforce bool) bool {
	if !enforce {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, base.Host)
}

func resolveURL(base *url.URL, raw string) string {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	out := base.ResolveReference(ref)
	out.Fragment = ""
	if out.Scheme != "http" && out.Scheme != "https" {
		return ""
	}
	return out.String()
}

func normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawQuery = ""
	return strings.TrimSuffix(u.String(), "/")
}
