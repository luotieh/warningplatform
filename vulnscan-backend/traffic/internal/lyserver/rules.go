package lyserver

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ruleItem 对应 ta_node 规则文件 (intel.*.yaml) items 列表中的一条规则。
// 本系统仅作只读展示，不提供上传/编辑能力。
type ruleItem struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Value       string   `json:"value"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Source      string   `json:"source"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
	CreatedAt   int64    `json:"created_at"`
	UpdatedAt   int64    `json:"updated_at"`
}

var (
	rulesMu       sync.Mutex
	rulesCache    []ruleItem
	rulesSig      string
	rulesModTime  time.Time
	rulesLoadedAt time.Time

	rulesPathMu         sync.RWMutex
	configuredRulesPath string // 管理端配置的规则读取路径（单个 yaml 文件或文件夹）
)

// SetConfiguredRulesPath 设置规则读取路径（单个 yaml 文件，或包含 yaml 的文件夹）。
// 注意：当前为进程内存储，进程重启后回退到环境变量/默认目录。
func SetConfiguredRulesPath(p string) {
	rulesPathMu.Lock()
	configuredRulesPath = strings.TrimSpace(p)
	rulesPathMu.Unlock()
}

// ConfiguredRulesPath 返回管理端配置的规则读取路径（未配置时为空）。
func ConfiguredRulesPath() string {
	rulesPathMu.RLock()
	defer rulesPathMu.RUnlock()
	return configuredRulesPath
}

// expandRulesPath 把一个路径展开为 yaml 文件列表：
// 指向文件 → 返回该文件；指向文件夹 → 返回其下所有 *.yaml/*.yml。
func expandRulesPath(p string) []string {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	if !st.IsDir() {
		return []string{p}
	}
	var matches []string
	for _, pat := range []string{"*.yaml", "*.yml"} {
		if m, err := filepath.Glob(filepath.Join(p, pat)); err == nil {
			matches = append(matches, m...)
		}
	}
	sort.Strings(matches)
	return matches
}

// resolveRulesFiles 定位 ta_node 规则文件。优先级：
// 1) 管理端配置路径(单文件/文件夹) 2) LY_RULES_FILE 3) LY_RULES_DIR 与候选目录。
func resolveRulesFiles() []string {
	if files := expandRulesPath(ConfiguredRulesPath()); len(files) > 0 {
		return files
	}
	if files := expandRulesPath(strings.TrimSpace(os.Getenv("LY_RULES_FILE"))); len(files) > 0 {
		return files
	}
	dirs := []string{
		strings.TrimSpace(os.Getenv("LY_RULES_DIR")),
		"configs", "./configs", "../configs", "../../configs", "/app/configs",
	}
	for _, d := range dirs {
		if files := expandRulesPath(d); len(files) > 0 {
			return files
		}
	}
	return nil
}

// loadRules 解析并缓存规则；文件 mtime 或文件集合变化时自动重载。
func loadRules() ([]ruleItem, string, time.Time, error) {
	files := resolveRulesFiles()
	sig := strings.Join(files, ";")
	var latest time.Time
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && st.ModTime().After(latest) {
			latest = st.ModTime()
		}
	}

	rulesMu.Lock()
	defer rulesMu.Unlock()
	if rulesCache != nil && rulesSig == sig && latest.Equal(rulesModTime) {
		return rulesCache, sig, rulesLoadedAt, nil
	}

	all := make([]ruleItem, 0)
	for _, f := range files {
		items, err := parseRuleFile(f)
		if err != nil {
			return nil, sig, time.Time{}, err
		}
		all = append(all, items...)
	}
	rulesCache = all
	rulesSig = sig
	rulesModTime = latest
	rulesLoadedAt = time.Now()
	return all, sig, rulesLoadedAt, nil
}

func parseRuleFile(path string) ([]ruleItem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	items := make([]ruleItem, 0, 1024)
	var cur *ruleItem
	flush := func() {
		if cur != nil {
			items = append(items, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024) // 容纳超长 description 行
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			// 新规则项；"- " 之后是第一个字段
			flush()
			cur = &ruleItem{}
			applyRuleKV(cur, strings.TrimPrefix(trimmed, "- "))
			continue
		}
		// 缩进字段行（排除顶层 "items:" 这类）
		if cur != nil && len(line) > len(trimmed) && strings.Contains(trimmed, ":") {
			applyRuleKV(cur, trimmed)
		}
	}
	flush()
	return items, sc.Err()
}

func applyRuleKV(it *ruleItem, kv string) {
	idx := strings.Index(kv, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(kv[:idx])
	val := strings.TrimSpace(kv[idx+1:])
	switch key {
	case "id":
		it.ID = unquoteYAML(val)
	case "type":
		it.Type = unquoteYAML(val)
	case "value":
		it.Value = unquoteYAML(val)
	case "category":
		it.Category = unquoteYAML(val)
	case "severity":
		it.Severity = unquoteYAML(val)
	case "source":
		it.Source = unquoteYAML(val)
	case "description":
		it.Description = unquoteYAML(val)
	case "enabled":
		it.Enabled = strings.EqualFold(unquoteYAML(val), "true")
	case "created_at":
		it.CreatedAt, _ = strconv.ParseInt(strings.TrimSpace(unquoteYAML(val)), 10, 64)
	case "updated_at":
		it.UpdatedAt, _ = strconv.ParseInt(strings.TrimSpace(unquoteYAML(val)), 10, 64)
	case "tags":
		it.Tags = parseInlineList(val)
	}
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		s = strings.ReplaceAll(s, `\"`, `"`)
		s = strings.ReplaceAll(s, `\\`, `\`)
		return s
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], `''`, `'`)
	}
	return s
}

func parseInlineList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := unquoteYAML(strings.TrimSpace(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Rules 只读返回 ta_node 规则，支持按类型/关键字过滤与分页。无需数据库。
func (s *Service) Rules(w http.ResponseWriter, r *http.Request) {
	items, src, loadedAt, err := loadRules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	params := readParams(r)

	typeFilter := strings.ToLower(strings.TrimSpace(firstNonEmpty(params["type"], params["rule_type"])))
	severity := strings.ToLower(strings.TrimSpace(params["severity"]))
	keyword := strings.ToLower(strings.TrimSpace(firstNonEmpty(params["keyword"], params["q"], params["search"])))

	typeCounts := map[string]int{}
	for i := range items {
		typeCounts[items[i].Type]++
	}

	filtered := items
	if typeFilter != "" || severity != "" || keyword != "" {
		out := make([]ruleItem, 0)
		for i := range items {
			it := items[i]
			if typeFilter != "" && strings.ToLower(it.Type) != typeFilter {
				continue
			}
			if severity != "" && strings.ToLower(it.Severity) != severity {
				continue
			}
			if keyword != "" {
				hay := strings.ToLower(it.Value + " " + it.ID + " " + it.Description + " " + it.Category + " " + it.Source)
				if !strings.Contains(hay, keyword) {
					continue
				}
			}
			out = append(out, it)
		}
		filtered = out
	}

	total := len(filtered)
	page := parseLimit(params["page"], 1)
	if page < 1 {
		page = 1
	}
	pageSize := parseLimit(firstNonEmpty(params["page_size"], params["pageSize"]), 20)
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 500 {
		pageSize = 500
	}
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	pageItems := filtered[start:end]
	if pageItems == nil {
		pageItems = []ruleItem{}
	}

	loaded := ""
	if !loadedAt.IsZero() {
		loaded = loadedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"result": "ok",
		"data": map[string]any{
			"items":       pageItems,
			"total":       total,
			"page":        page,
			"page_size":   pageSize,
			"type_counts": typeCounts,
			"source_file": src,
			"loaded_at":   loaded,
			"read_only":   true,
		},
	})
}

// RulesConfig：GET 返回当前规则读取路径与解析情况；POST 设置规则读取路径。
// POST body: {"path": "<单个 yaml 文件，或包含 yaml 的文件夹>"}（path 为空表示恢复默认探测）。
func (s *Service) RulesConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			Path string `json:"path"`
		}
		if data, _ := io.ReadAll(r.Body); len(data) > 0 {
			_ = json.Unmarshal(data, &body)
		}
		p := strings.TrimSpace(body.Path)
		if p != "" {
			st, err := os.Stat(p)
			if err != nil {
				writeError(w, http.StatusBadRequest, "路径不存在或不可访问："+p)
				return
			}
			if st.IsDir() {
				if len(expandRulesPath(p)) == 0 {
					writeError(w, http.StatusBadRequest, "该文件夹下未找到 .yaml/.yml 规则文件")
					return
				}
			} else {
				ext := strings.ToLower(filepath.Ext(p))
				if ext != ".yaml" && ext != ".yml" {
					writeError(w, http.StatusBadRequest, "单文件必须是 .yaml 或 .yml")
					return
				}
			}
		}
		SetConfiguredRulesPath(p)
	}

	files := resolveRulesFiles()
	mode := "auto"
	if cp := ConfiguredRulesPath(); cp != "" {
		if st, err := os.Stat(cp); err == nil && st.IsDir() {
			mode = "folder"
		} else {
			mode = "file"
		}
	}
	items, _, loadedAt, err := loadRules()
	loaded := ""
	if !loadedAt.IsZero() {
		loaded = loadedAt.Format(time.RFC3339)
	}
	data := map[string]any{
		"path":           ConfiguredRulesPath(),
		"mode":           mode, // file=单文件, folder=文件夹, auto=默认探测
		"resolved_files": files,
		"file_count":     len(files),
		"rule_count":     len(items),
		"loaded_at":      loaded,
	}
	if err != nil {
		data["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": data})
}
