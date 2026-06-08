package aifingerprint

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// AssetCorrelator 资产关联分析器。
// 从扫描/资产发现结果中收集实体信息，通过 NLP 发现隐藏关联。
type AssetCorrelator struct {
	svc      *EnhancedService
	mu       sync.RWMutex
	entities []EntityInfo
	results  []AssetRelation
}

// NewAssetCorrelator 创建资产关联分析器。
func NewAssetCorrelator(svc *EnhancedService) *AssetCorrelator {
	return &AssetCorrelator{svc: svc}
}

// AddEntity 添加已发现的资产实体到分析池。
func (c *AssetCorrelator) AddEntity(entity EntityInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.entities {
		if existing.Host == entity.Host {
			return
		}
	}
	c.entities = append(c.entities, entity)
}

// AddEntities 批量添加实体。
func (c *AssetCorrelator) AddEntities(entities []EntityInfo) {
	for _, e := range entities {
		c.AddEntity(e)
	}
}

// Analyze 执行关联分析。
// 当实体数量超过阈值时，分批进行分析以避免 prompt 过长。
func (c *AssetCorrelator) Analyze(ctx context.Context) ([]AssetRelation, error) {
	c.mu.RLock()
	entities := make([]EntityInfo, len(c.entities))
	copy(entities, c.entities)
	c.mu.RUnlock()

	if len(entities) < 2 {
		return nil, nil
	}

	const batchSize = 20

	var allRelations []AssetRelation

	if len(entities) <= batchSize {
		relations, err := c.svc.AnalyzeRelations(ctx, entities)
		if err != nil {
			return nil, err
		}
		allRelations = relations
	} else {
		// 分批分析 + 跨批关联
		batches := splitEntities(entities, batchSize)
		for i, batch := range batches {
			relations, err := c.svc.AnalyzeRelations(ctx, batch)
			if err != nil {
				slog.Warn("[AssetCorrelator] batch analysis failed",
					"batch", i, "error", err)
				continue
			}
			allRelations = append(allRelations, relations...)
		}

		// 跨批次关联：取每批中高关联度的实体做二次分析
		if len(batches) > 1 {
			crossBatch := extractHighConfidenceEntities(entities, allRelations)
			if len(crossBatch) >= 2 {
				crossRelations, err := c.svc.AnalyzeRelations(ctx, crossBatch)
				if err == nil {
					allRelations = append(allRelations, crossRelations...)
				}
			}
		}
	}

	allRelations = deduplicateRelations(allRelations)

	c.mu.Lock()
	c.results = allRelations
	c.mu.Unlock()

	return allRelations, nil
}

// GetResults 获取最近一次分析结果。
func (c *AssetCorrelator) GetResults() []AssetRelation {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.results
}

// GetEntitiesCount 获取当前实体池大小。
func (c *AssetCorrelator) GetEntitiesCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entities)
}

// FilterByType 按关联类型过滤结果。
func (c *AssetCorrelator) FilterByType(relType string) []AssetRelation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var filtered []AssetRelation
	for _, r := range c.results {
		if r.RelType == relType {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// GetTakeoverCandidates 获取可能被子域名接管的资产。
func (c *AssetCorrelator) GetTakeoverCandidates() []AssetRelation {
	return c.FilterByType("takeover_candidate")
}

// GetShadowIT 获取影子 IT 资产。
func (c *AssetCorrelator) GetShadowIT() []AssetRelation {
	return c.FilterByType("shadow_it")
}

func splitEntities(entities []EntityInfo, batchSize int) [][]EntityInfo {
	var batches [][]EntityInfo
	for i := 0; i < len(entities); i += batchSize {
		end := i + batchSize
		if end > len(entities) {
			end = len(entities)
		}
		batches = append(batches, entities[i:end])
	}
	return batches
}

func extractHighConfidenceEntities(entities []EntityInfo, relations []AssetRelation) []EntityInfo {
	mentionedHosts := make(map[string]struct{})
	for _, r := range relations {
		if r.Confidence >= 0.7 {
			mentionedHosts[r.SourceHost] = struct{}{}
			mentionedHosts[r.RelatedHost] = struct{}{}
		}
	}

	var result []EntityInfo
	for _, e := range entities {
		if _, ok := mentionedHosts[e.Host]; ok {
			result = append(result, e)
		}
	}
	return result
}

func deduplicateRelations(relations []AssetRelation) []AssetRelation {
	seen := make(map[string]struct{})
	var unique []AssetRelation
	for _, r := range relations {
		key := strings.Join([]string{r.SourceHost, r.RelatedHost, r.RelType}, "|")
		reverseKey := strings.Join([]string{r.RelatedHost, r.SourceHost, r.RelType}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		if _, ok := seen[reverseKey]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, r)
	}
	return unique
}
