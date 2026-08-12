package service

import "strings"

// maxEvidenceFiles 限制单条聚合事件保留的证据附件数量，与 maxOccurrences 对齐，
// 避免聚合事件 context 无限膨胀。
const maxEvidenceFiles = 200

// normalizeEvidenceFiles 给节点推送的 evidence_files 注入管理端聚合元数据：
// device_id（来源节点）、occ_idx（全局命中序号，首条=0）、occ_time（命中时间）。
// 元素保持节点原始字段；非数组/空数组返回 nil。
func normalizeEvidenceFiles(ly map[string]any, occIdx int, occTime string) []any {
	raw, ok := ly["evidence_files"].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	deviceID := asString(ly["device_id"])
	out := make([]any, 0, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		clone := make(map[string]any, len(m)+3)
		for k, v := range m {
			clone[k] = v
		}
		clone["device_id"] = deviceID
		clone["occ_idx"] = occIdx
		clone["occ_time"] = occTime
		out = append(out, clone)
	}
	return out
}

// evidenceDedupKey 返回附件去重键：sha256 非空时优先，否则 path_ref。
func evidenceDedupKey(ef map[string]any) string {
	if k := strings.TrimSpace(asString(ef["sha256"])); k != "" {
		return "sha256:" + k
	}
	if k := strings.TrimSpace(asString(ef["path_ref"])); k != "" {
		return "path:" + k
	}
	return ""
}

// mergeEvidenceFiles 把新命中证据合并进 ctx["evidence_files"]：
// 按去重键跳过已存在附件；超过 maxEvidenceFiles 时丢弃新文件并标记
// evidence_truncated=true。返回是否新增了附件。
func mergeEvidenceFiles(ctx map[string]any, files []any) bool {
	if len(files) == 0 {
		return false
	}
	existing, _ := ctx["evidence_files"].([]any)
	seen := make(map[string]struct{}, len(existing)+len(files))
	for _, item := range existing {
		if m, ok := item.(map[string]any); ok {
			if k := evidenceDedupKey(m); k != "" {
				seen[k] = struct{}{}
			}
		}
	}
	added := false
	for _, item := range files {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		k := evidenceDedupKey(m)
		if k != "" {
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
		}
		if len(existing) >= maxEvidenceFiles {
			ctx["evidence_truncated"] = true
			continue
		}
		existing = append(existing, item)
		added = true
	}
	if added {
		ctx["evidence_files"] = existing
	}
	return added
}
