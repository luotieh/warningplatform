package monitoragent

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"
)

type CrawlResult struct {
	Pages      []CrawledPage `json:"pages"`
	TotalFound int           `json:"total_found"`
	Crawled    int           `json:"crawled"`
	Errors     int           `json:"errors"`
	Duration   float64       `json:"duration_ms"`
}

type CrawledPage struct {
	URL         string  `json:"url"`
	Title       string  `json:"title"`
	StatusCode  int     `json:"status_code"`
	ContentLen  int     `json:"content_len"`
	ResponseMS  float64 `json:"response_ms"`
	Error       string  `json:"error,omitempty"`
	LinksFound  int     `json:"links_found"`
	IsExternal  bool    `json:"is_external"`
	ContentHash string  `json:"content_hash"`
}

type Crawler struct {
	ps          *PageService
	maxPages    int
	maxDepth    int
	concurrency int
	sameHost    bool
}

func NewCrawler(ps *PageService, maxPages, maxDepth, concurrency int) *Crawler {
	if maxPages <= 0 {
		maxPages = 20
	}
	if maxDepth <= 0 {
		maxDepth = 2
	}
	if concurrency <= 0 {
		concurrency = 3
	}
	return &Crawler{
		ps:          ps,
		maxPages:    maxPages,
		maxDepth:    maxDepth,
		concurrency: concurrency,
		sameHost:    true,
	}
}

func (c *Crawler) Crawl(ctx context.Context, startURL string) *CrawlResult {
	start := time.Now()
	result := &CrawlResult{}

	baseURL, err := url.Parse(startURL)
	if err != nil {
		return result
	}

	visited := &sync.Map{}
	var mu sync.Mutex
	var pages []CrawledPage

	type crawlItem struct {
		url   string
		depth int
	}

	queue := make(chan crawlItem, c.maxPages*10)
	queue <- crawlItem{url: startURL, depth: 0}
	visited.Store(normalizeURL(startURL), true)

	var wg sync.WaitGroup
	sem := make(chan struct{}, c.concurrency)

	crawled := 0
	errors := 0

	for i := 0; i < c.maxPages; i++ {
		select {
		case <-ctx.Done():
			goto done
		case item, ok := <-queue:
			if !ok {
				goto done
			}

			mu.Lock()
			if crawled >= c.maxPages {
				mu.Unlock()
				goto done
			}
			crawled++
			mu.Unlock()

			wg.Add(1)
			sem <- struct{}{}
			go func(item crawlItem) {
				defer wg.Done()
				defer func() { <-sem }()

				snap, fetchErr := c.ps.FetchPage(ctx, item.url)

				page := CrawledPage{
					URL:        item.url,
					IsExternal: false,
				}

				if fetchErr != nil || snap == nil {
					page.Error = "fetch failed"
					if fetchErr != nil {
						page.Error = fetchErr.Error()
					}
					mu.Lock()
					errors++
					pages = append(pages, page)
					mu.Unlock()
					return
				}

				page.Title = snap.Title
				page.StatusCode = snap.StatusCode
				page.ContentLen = len(snap.RenderedHTML)
				page.ResponseMS = snap.TotalMS
				page.ContentHash = snap.ContentHash
				page.LinksFound = len(snap.Links)

				mu.Lock()
				pages = append(pages, page)
				mu.Unlock()

				if item.depth >= c.maxDepth {
					return
				}

				for _, link := range snap.Links {
					linkURL := resolveURL(baseURL, link.URL)
					if linkURL == "" {
						continue
					}

					normalized := normalizeURL(linkURL)
					if _, loaded := visited.LoadOrStore(normalized, true); loaded {
						continue
					}

					parsedLink, perr := url.Parse(linkURL)
					if perr != nil {
						continue
					}
					if c.sameHost && parsedLink.Host != baseURL.Host {
						continue
					}

					select {
					case queue <- crawlItem{url: linkURL, depth: item.depth + 1}:
					default:
					}
				}
			}(item)

		case <-time.After(100 * time.Millisecond):
			if crawled >= c.maxPages {
				goto done
			}
			if len(queue) == 0 {
				goto done
			}
		}
	}

done:
	wg.Wait()

	result.Pages = pages
	result.TotalFound = len(pages)
	result.Crawled = crawled
	result.Errors = errors
	result.Duration = float64(time.Since(start).Milliseconds())

	slog.Info("[Crawler] done",
		"start_url", startURL,
		"crawled", crawled,
		"errors", errors,
		"duration_ms", result.Duration)

	return result
}

func resolveURL(base *url.URL, raw string) string {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") {
		return ""
	}

	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)
	resolved.Fragment = ""

	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}

func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawQuery = ""
	result := u.String()
	result = strings.TrimSuffix(result, "/")
	return result
}
