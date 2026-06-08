package aifingerprint

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RAGStore 指纹知识检索增强存储。
// 通过已知指纹规则集作为 few-shot 参考，帮助 LLM 更准确地识别新型设备。
type RAGStore struct {
	mu      sync.RWMutex
	entries []RAGEntry
}

// RAGEntry 知识库条目。
type RAGEntry struct {
	ID          string   `json:"id"`
	Product     string   `json:"product"`
	Vendor      string   `json:"vendor"`
	Category    string   `json:"category"`
	Patterns    []string `json:"patterns"`    // Banner/Header 中的关键特征
	HTMLClues   []string `json:"html_clues"`  // HTML 中的指纹线索
	Description string   `json:"description"` // 自然语言描述
}

// NewRAGStore 创建 RAG 存储。
func NewRAGStore() *RAGStore {
	store := &RAGStore{}
	store.loadBuiltinEntries()
	return store
}

// Search 基于关键词相似度检索相关的已知指纹条目，作为 LLM 的 few-shot 参考。
func (r *RAGStore) Search(_ context.Context, query string, topK int) []RAGEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if topK <= 0 {
		topK = 5
	}

	type scored struct {
		entry RAGEntry
		score float64
	}

	queryLower := strings.ToLower(query)
	queryTokens := tokenize(queryLower)

	var results []scored
	for _, e := range r.entries {
		score := computeRelevance(queryTokens, e)
		if score > 0 {
			results = append(results, scored{entry: e, score: score})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	if len(results) > topK {
		results = results[:topK]
	}

	out := make([]RAGEntry, len(results))
	for i, r := range results {
		out[i] = r.entry
	}
	return out
}

// AddEntry 动态添加新发现的指纹到知识库（学习能力）。
func (r *RAGStore) AddEntry(entry RAGEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entry)
}

// Count 返回当前知识库条目数量。
func (r *RAGStore) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

func computeRelevance(queryTokens []string, entry RAGEntry) float64 {
	var score float64
	entryText := strings.ToLower(fmt.Sprintf("%s %s %s %s %s",
		entry.Product, entry.Vendor, entry.Category,
		strings.Join(entry.Patterns, " "),
		strings.Join(entry.HTMLClues, " ")))

	for _, token := range queryTokens {
		if strings.Contains(entryText, token) {
			score += 1.0
			if strings.Contains(strings.ToLower(entry.Product), token) {
				score += 2.0 // 产品名匹配权重更高
			}
		}
	}
	return score
}

func tokenize(s string) []string {
	replacer := strings.NewReplacer(
		"/", " ", ":", " ", ";", " ", ",", " ",
		"(", " ", ")", " ", "<", " ", ">", " ",
		"=", " ", "\"", " ", "'", " ",
	)
	s = replacer.Replace(s)
	words := strings.Fields(s)
	var tokens []string
	for _, w := range words {
		w = strings.TrimSpace(w)
		if len(w) >= 2 {
			tokens = append(tokens, w)
		}
	}
	return tokens
}

// loadBuiltinEntries 加载内置的典型指纹参考。
func (r *RAGStore) loadBuiltinEntries() {
	r.entries = []RAGEntry{
		{
			ID: "nginx", Product: "Nginx", Vendor: "F5/Nginx Inc", Category: "web_server",
			Patterns:  []string{"nginx/", "Server: nginx"},
			HTMLClues: []string{"<center>nginx</center>"},
		},
		{
			ID: "apache", Product: "Apache HTTP Server", Vendor: "Apache Software Foundation", Category: "web_server",
			Patterns:  []string{"Apache/", "Server: Apache"},
			HTMLClues: []string{"Apache Server at"},
		},
		{
			ID: "tomcat", Product: "Apache Tomcat", Vendor: "Apache Software Foundation", Category: "middleware",
			Patterns:  []string{"Apache-Coyote", "Tomcat/"},
			HTMLClues: []string{"Apache Tomcat", "Tomcat Home Page"},
		},
		{
			ID: "iis", Product: "Microsoft IIS", Vendor: "Microsoft", Category: "web_server",
			Patterns:  []string{"Microsoft-IIS/", "Server: Microsoft-IIS"},
			HTMLClues: []string{"IIS Windows Server"},
		},
		{
			ID: "spring_boot", Product: "Spring Boot", Vendor: "VMware/Pivotal", Category: "framework",
			Patterns:  []string{"X-Application-Context", "Whitelabel Error Page"},
			HTMLClues: []string{"Whitelabel Error Page", "spring"},
		},
		{
			ID: "shiro", Product: "Apache Shiro", Vendor: "Apache Software Foundation", Category: "framework",
			Patterns:  []string{"rememberMe=deleteMe", "Set-Cookie: JSESSIONID"},
			HTMLClues: []string{},
		},
		{
			ID: "nacos", Product: "Nacos", Vendor: "Alibaba", Category: "middleware",
			Patterns:  []string{"Nacos", "nacos/v"},
			HTMLClues: []string{"Nacos", "nacosserver"},
		},
		{
			ID: "fastjson", Product: "Fastjson", Vendor: "Alibaba", Category: "library",
			Patterns:  []string{"fastjson"},
			HTMLClues: []string{},
		},
		{
			ID: "weblogic", Product: "WebLogic Server", Vendor: "Oracle", Category: "middleware",
			Patterns:  []string{"WebLogic", "wl_authcookie"},
			HTMLClues: []string{"WebLogic Server", "bea_wls_"},
		},
		{
			ID: "dameng", Product: "达梦数据库", Vendor: "达梦信息技术", Category: "database",
			Patterns:  []string{"DM Database", "DM8", "DMSERVER"},
			HTMLClues: []string{"达梦", "Dameng"},
		},
		{
			ID: "kingbase", Product: "人大金仓", Vendor: "北京人大金仓信息技术", Category: "database",
			Patterns:  []string{"KingbaseES", "Kingbase"},
			HTMLClues: []string{"人大金仓", "KingBase"},
		},
		{
			ID: "tongweb", Product: "东方通 TongWeb", Vendor: "东方通", Category: "middleware",
			Patterns:  []string{"TongWeb", "TW_JSESSIONID"},
			HTMLClues: []string{"TongWeb Application Server", "东方通"},
		},
		{
			ID: "kylin_os", Product: "银河麒麟", Vendor: "麒麟软件", Category: "os",
			Patterns:  []string{"Kylin", "kylin"},
			HTMLClues: []string{"银河麒麟", "Kylin OS"},
		},
		{
			ID: "hikvision", Product: "海康威视", Vendor: "海康威视", Category: "iot",
			Patterns:  []string{"DNVRS-Webs", "App-webs", "DVRDVS-Webs"},
			HTMLClues: []string{"海康威视", "HIKVISION", "doc/page/login"},
		},
		{
			ID: "dahua", Product: "大华", Vendor: "浙江大华", Category: "iot",
			Patterns:  []string{"DH_WEB", "DHVideo"},
			HTMLClues: []string{"大华", "Dahua", "ui/login"},
		},
		{
			ID: "sangfor_af", Product: "深信服 AF", Vendor: "深信服", Category: "network_device",
			Patterns:  []string{"SANGFOR", "AF_SESSION"},
			HTMLClues: []string{"深信服", "SANGFOR", "login/login.html"},
		},
		{
			ID: "huawei_switch", Product: "华为交换机", Vendor: "华为", Category: "network_device",
			Patterns:  []string{"HUAWEI", "VRP", "Comware"},
			HTMLClues: []string{"华为", "HUAWEI"},
		},
		{
			ID: "ruijie", Product: "锐捷网络设备", Vendor: "锐捷网络", Category: "network_device",
			Patterns:  []string{"Ruijie", "RG-"},
			HTMLClues: []string{"锐捷", "Ruijie", "eportal"},
		},
		{
			ID: "yonyou_nc", Product: "用友 NC", Vendor: "用友", Category: "middleware",
			Patterns:  []string{"NCCloud", "nc/servlet"},
			HTMLClues: []string{"用友", "NC Cloud", "nccloud"},
		},
		{
			ID: "seeyon", Product: "致远 OA", Vendor: "致远互联", Category: "middleware",
			Patterns:  []string{"Seeyon", "A8", "seeyonreport"},
			HTMLClues: []string{"致远", "seeyon", "A8-V5"},
		},
	}
}
