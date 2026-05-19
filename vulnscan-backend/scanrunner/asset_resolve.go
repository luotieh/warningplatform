package scanrunner

import (
	"fmt"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/assethost"
)

// AssetIDResolver 根据任务 parameters 中的资产绑定解析 finding 所属资产，不按全局域名表匹配。
type AssetIDResolver struct {
	defaultAssetID string
	byTarget       map[string]string
}

// BuildAssetIDResolver 从任务 parameters（asset_id / asset_ids / asset_bindings）与 targets 构建解析器。
func BuildAssetIDResolver(task *model.ScanTask) *AssetIDResolver {
	r := &AssetIDResolver{byTarget: map[string]string{}}
	if task == nil {
		return r
	}

	if task.Parameters != nil {
		parseAssetBindings(task.Parameters, r.byTarget)
		if id, ok := stringFromJSONMap(task.Parameters, "asset_id"); ok && id != "" {
			r.defaultAssetID = id
		}
	}

	ids := stringSliceFromJSONMap(task.Parameters, "asset_ids")
	targets := task.Targets
	if len(ids) == len(targets) && len(ids) > 0 {
		for i := range ids {
			aid := strings.TrimSpace(ids[i])
			if aid == "" {
				continue
			}
			for _, key := range targetLookupKeys(targets[i], 0) {
				r.byTarget[key] = aid
			}
		}
		// 多目标一一绑定时不再使用「全任务默认 asset_id」，避免串资产
		if len(r.byTarget) > 0 {
			r.defaultAssetID = ""
		}
	}

	// 单资产富化：仅一个 asset_id 且无按目标映射时，全部发现归属该资产
	if r.defaultAssetID != "" && len(r.byTarget) == 0 {
		return r
	}
	if r.defaultAssetID != "" && len(targets) == 1 {
		for _, key := range targetLookupKeys(targets[0], 0) {
			r.byTarget[key] = r.defaultAssetID
		}
	}
	return r
}

// Resolve 返回 finding 应对应的 asset_id；无绑定则返回空字符串。
func (r *AssetIDResolver) Resolve(target string, port int) string {
	if r == nil {
		return ""
	}
	for _, key := range targetLookupKeys(target, port) {
		if id, ok := r.byTarget[key]; ok && id != "" {
			return id
		}
	}
	return strings.TrimSpace(r.defaultAssetID)
}

// NormalizeTaskAssetParameters 在任务入库前写入 asset_bindings，供子任务继承与持久化解析。
func NormalizeTaskAssetParameters(params model.JSONMap, targets []string) {
	if params == nil {
		return
	}
	ids := stringSliceFromJSONMap(params, "asset_ids")
	if len(ids) == len(targets) && len(targets) > 0 {
		params["asset_bindings"] = buildAssetBindings(targets, ids)
		return
	}
	if id, ok := stringFromJSONMap(params, "asset_id"); ok && id != "" && len(targets) == 1 {
		params["asset_bindings"] = buildAssetBindings(targets, []string{id})
	}
}

// MergeAssetIDsIntoParameters 启动扫描时合并资产 ID（漏扫/富化通用）。
func MergeAssetIDsIntoParameters(params map[string]interface{}, targets []string, assetIDs []string) map[string]interface{} {
	if params == nil {
		params = map[string]interface{}{}
	}
	cleanIDs := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		if id = strings.TrimSpace(id); id != "" {
			cleanIDs = append(cleanIDs, id)
		}
	}
	if len(cleanIDs) == 1 {
		params["asset_id"] = cleanIDs[0]
	}
	if len(cleanIDs) > 0 {
		params["asset_ids"] = cleanIDs
	}
	if len(cleanIDs) == len(targets) && len(targets) > 0 {
		params["asset_bindings"] = buildAssetBindings(targets, cleanIDs)
	}
	return params
}

func buildAssetBindings(targets, assetIDs []string) []map[string]string {
	out := make([]map[string]string, 0, len(targets))
	for i := range targets {
		out = append(out, map[string]string{
			"asset_id": strings.TrimSpace(assetIDs[i]),
			"target":   strings.TrimSpace(targets[i]),
		})
	}
	return out
}

func parseAssetBindings(params model.JSONMap, into map[string]string) {
	raw, ok := params["asset_bindings"]
	if !ok || raw == nil {
		return
	}
	switch list := raw.(type) {
	case []map[string]string:
		for _, item := range list {
			addBinding(into, item["target"], item["asset_id"])
		}
	case []interface{}:
		for _, it := range list {
			m, ok := it.(map[string]interface{})
			if !ok {
				continue
			}
			addBinding(into, fmt.Sprint(m["target"]), fmt.Sprint(m["asset_id"]))
		}
	}
}

func addBinding(into map[string]string, target, assetID string) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return
	}
	for _, key := range targetLookupKeys(target, 0) {
		into[key] = assetID
	}
}

func targetLookupKeys(target string, port int) []string {
	host := assethost.ExtractHost(target)
	if host == "" {
		host = strings.TrimSpace(target)
	}
	if host == "" {
		return nil
	}
	keys := []string{host}
	if port > 0 {
		keys = append(keys, fmt.Sprintf("%s:%d", host, port))
	}
	trimmed := strings.TrimSpace(target)
	if trimmed != "" && trimmed != host {
		keys = append(keys, trimmed)
	}
	return keys
}
