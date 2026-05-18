package asm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type ConcurrentDiscoveryEngine struct {
	collectors []AssetCollector
	maxWorkers int
	timeout    time.Duration
}

func NewConcurrentDiscoveryEngine(maxWorkers int, timeout time.Duration, extraCollectors ...AssetCollector) *ConcurrentDiscoveryEngine {
	if maxWorkers <= 0 {
		maxWorkers = 10
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	collectors := []AssetCollector{
		&DNSCollector{},
		&ReverseDNSCollector{},
		&CertCollector{},
	}
	collectors = append(collectors, extraCollectors...)

	return &ConcurrentDiscoveryEngine{
		collectors: collectors,
		maxWorkers: maxWorkers,
		timeout:    timeout,
	}
}

func (e *ConcurrentDiscoveryEngine) Discover(ctx context.Context, project *ASMProject) ([]DiscoveredAsset, error) {
	assetCh := make(chan DiscoveredAsset, 1024)
	errCh := make(chan error, len(e.collectors))

	var wg sync.WaitGroup
	sem := make(chan struct{}, e.maxWorkers)

	for _, collector := range e.collectors {
		wg.Add(1)
		go func(c AssetCollector) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			collectCtx, cancel := context.WithTimeout(ctx, e.timeout)
			defer cancel()

			for _, seed := range project.Seeds {
				select {
				case <-collectCtx.Done():
					return
				default:
				}

				assets, err := c.Collect(collectCtx, seed)
				if err != nil {
					slog.Warn("ASM并发收集器失败",
						"collector", c.Name(),
						"seed", seed.Value,
						"error", err,
					)
					select {
					case errCh <- fmt.Errorf("%s: %w", c.Name(), err):
					default:
					}
					continue
				}

				for _, a := range assets {
					select {
					case assetCh <- a:
					case <-collectCtx.Done():
						return
					}
				}
			}
		}(collector)
	}

	go func() {
		wg.Wait()
		close(assetCh)
		close(errCh)
	}()

	return streamDedupAndScore(ctx, assetCh, errCh)
}

func streamDedupAndScore(ctx context.Context, input <-chan DiscoveredAsset, errCh <-chan error) ([]DiscoveredAsset, error) {
	seen := make(map[string]int) // key → index in results
	var results []DiscoveredAsset
	scorer := NewRiskScorer()

	var errs []error
	go func() {
		for err := range errCh {
			errs = append(errs, err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if len(errs) > 0 {
				return results, fmt.Errorf("部分收集器失败: %v", errs)
			}
			return results, ctx.Err()
		case asset, ok := <-input:
			if !ok {
				if len(errs) > 0 {
					return results, fmt.Errorf("部分收集器失败: %v", errs)
				}
				return results, nil
			}

			key := normalizeAssetKey(asset)
			if idx, exists := seen[key]; exists {
				for k, v := range asset.Attributes {
					if results[idx].Attributes == nil {
						results[idx].Attributes = make(map[string]string)
					}
					results[idx].Attributes[k] = v
				}
				if asset.Source != results[idx].Source {
					results[idx].Source += "," + asset.Source
				}
				results[idx].RiskScore = scorer.Calculate(results[idx])
			} else {
				seen[key] = len(results)
				asset.FirstSeen = time.Now()
				asset.LastSeen = time.Now()
				asset.Status = "active"
				asset.RiskScore = scorer.Calculate(asset)
				results = append(results, asset)
			}
		}
	}
}

func normalizeAssetKey(asset DiscoveredAsset) string {
	value := asset.Value
	switch asset.Type {
	case "domain", "subdomain":
		value = normalizeDomain(value)
	case "ip":
		value = normalizeIP(value)
	}
	return asset.Type + "|" + value
}

func normalizeDomain(domain string) string {
	domain = stripWildcard(domain)
	return domain
}

func stripWildcard(domain string) string {
	if len(domain) > 2 && domain[0] == '*' && domain[1] == '.' {
		return domain[2:]
	}
	return domain
}

func normalizeIP(ip string) string {
	return ip
}
