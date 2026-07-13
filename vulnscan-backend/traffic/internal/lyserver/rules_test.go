package lyserver

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeTempRuleFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "intel.test.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写临时规则文件失败: %v", err)
	}
	return p
}

// 新版 intel.yaml：块式 tags/threat_labels 列表、evidence 证据块、多行折行 description。
func TestParseRuleFileNewFormat(t *testing.T) {
	content := `items:
- id: 763001ec-d29d-4ff2-8f92-b32e786ce33d
  type: domain
  value: ip-scanner.org
  category: c2
  severity: high
  source: Threat Intel Hub
  description: '命中威胁: Bumblebee and AdaptixC2 Deliver
    Akira | 关联: rustdesk, akira | TLP:WHITE'
  evidence:
    activity: 'From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira'
    threat_labels:
    - rustdesk
    - trojanized installer
    - lateral movement
    source: otx
    cross_check: WhoisXML=malware, seen 2025-08-07~2026-07-06
    confidence: high (2 sources)
    tlp: white
    misp_event_id: '2167'
    narrative: 建议立即阻断该域名的访问。
  recommended_action: block_and_report
  tags:
  - source:otx
  - tlp:white
  - otx:tag="rustdesk"
  enabled: true
  created_at: 1783412454
  updated_at: 1783416113
- id: second-rule
  type: ip
  value: 10.1.2.3
  category: scanner
  severity: medium
  source: Threat Intel Hub
  description: second
  recommended_action: monitor
  tags:
  - source:otx
  enabled: false
  created_at: 1
  updated_at: 2
`
	items, err := parseRuleFile(writeTempRuleFile(t, content))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("期望 2 条规则（块式列表不应被误判为新规则项），实得 %d", len(items))
	}

	it := items[0]
	if it.ID != "763001ec-d29d-4ff2-8f92-b32e786ce33d" || it.Type != "domain" || it.Value != "ip-scanner.org" {
		t.Errorf("基础字段解析错误: %+v", it)
	}
	if it.Category != "c2" || it.Severity != "high" || it.Source != "Threat Intel Hub" {
		t.Errorf("category/severity/source 解析错误: %+v", it)
	}
	if it.Description != "命中威胁: Bumblebee and AdaptixC2 Deliver Akira | 关联: rustdesk, akira | TLP:WHITE" {
		t.Errorf("多行折行 description 解析错误: %q", it.Description)
	}
	if it.RecommendedAction != "block_and_report" {
		t.Errorf("recommended_action 解析错误: %q", it.RecommendedAction)
	}
	if len(it.Tags) != 3 || it.Tags[0] != "source:otx" || it.Tags[2] != `otx:tag="rustdesk"` {
		t.Errorf("块式 tags 解析错误: %v", it.Tags)
	}
	if !it.Enabled || it.CreatedAt != 1783412454 || it.UpdatedAt != 1783416113 {
		t.Errorf("enabled/created_at/updated_at 解析错误: %+v", it)
	}
	ev := it.Evidence
	if ev == nil {
		t.Fatal("evidence 未解析")
	}
	if ev.Activity == "" || ev.Source != "otx" || ev.Confidence != "high (2 sources)" ||
		ev.TLP != "white" || ev.MISPEventID != "2167" || ev.Narrative != "建议立即阻断该域名的访问。" ||
		ev.CrossCheck != "WhoisXML=malware, seen 2025-08-07~2026-07-06" {
		t.Errorf("evidence 字段解析错误: %+v", ev)
	}
	if len(ev.ThreatLabels) != 3 || ev.ThreatLabels[1] != "trojanized installer" {
		t.Errorf("threat_labels 解析错误: %v", ev.ThreatLabels)
	}
	// 嵌套的 evidence.source 不得覆盖顶层 source
	if it.Source != "Threat Intel Hub" {
		t.Errorf("evidence.source 覆盖了顶层 source: %q", it.Source)
	}

	second := items[1]
	if second.ID != "second-rule" || second.Enabled || second.RecommendedAction != "monitor" {
		t.Errorf("第二条规则解析错误: %+v", second)
	}
	if second.Evidence != nil {
		t.Errorf("无 evidence 的规则应为 nil, 实得 %+v", second.Evidence)
	}
}

// 旧版格式（内联 tags 列表）也必须能由标准 YAML 路径解析。
func TestParseRuleFileLegacyInlineFormat(t *testing.T) {
	content := `items:
- id: old-1
  type: domain
  value: legacy.example.com
  category: c2
  severity: low
  source: ta_node
  description: "legacy \"quoted\" desc"
  tags: ["a", "b"]
  enabled: true
  created_at: 100
  updated_at: 200
`
	items, err := parseRuleFile(writeTempRuleFile(t, content))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("期望 1 条规则, 实得 %d", len(items))
	}
	it := items[0]
	if it.ID != "old-1" || it.Description != `legacy "quoted" desc` {
		t.Errorf("旧格式字段解析错误: %+v", it)
	}
	if len(it.Tags) != 2 || it.Tags[0] != "a" || it.Tags[1] != "b" {
		t.Errorf("内联 tags 解析错误: %v", it.Tags)
	}
}

// 非法 YAML（历史宽松文件）回退到旧的逐行解析器，不报错。
func TestParseRuleFileFallbackToLegacy(t *testing.T) {
	content := `items:
- id: bad-1
  type: domain
  value: fallback.example.com
  description: hit: colon: makes: this: invalid yaml
  enabled: true
`
	items, err := parseRuleFile(writeTempRuleFile(t, content))
	if err != nil {
		t.Fatalf("回退解析失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("期望 1 条规则, 实得 %d", len(items))
	}
	it := items[0]
	if it.ID != "bad-1" || it.Value != "fallback.example.com" || !it.Enabled {
		t.Errorf("回退解析字段错误: %+v", it)
	}
	if it.Description != "hit: colon: makes: this: invalid yaml" {
		t.Errorf("回退解析 description 错误: %q", it.Description)
	}
}

// 空 items 与空文件不报错、返回空列表。
func TestParseRuleFileEmpty(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "noItems": "items: []\n"} {
		items, err := parseRuleFile(writeTempRuleFile(t, content))
		if err != nil {
			t.Fatalf("%s: 解析失败: %v", name, err)
		}
		if len(items) != 0 {
			t.Fatalf("%s: 期望 0 条规则, 实得 %d", name, len(items))
		}
	}
}

// Rules HTTP handler：新字段应出现在 JSON 响应里，且关键字搜索覆盖证据块/处置建议。
func TestRulesHandlerNewFields(t *testing.T) {
	content := `items:
- id: rule-a
  type: domain
  value: evil.example.org
  category: c2
  severity: high
  source: Threat Intel Hub
  description: 命中威胁
  evidence:
    activity: Sample Campaign
    threat_labels:
    - akira
    misp_event_id: '2167'
    narrative: 建议阻断。
  recommended_action: block_and_report
  tags:
  - source:otx
  enabled: true
  created_at: 1783412454
  updated_at: 1783416113
- id: rule-b
  type: ip
  value: 10.9.8.7
  category: scanner
  severity: low
  source: ta_node
  description: 扫描器
  recommended_action: monitor
  enabled: true
  created_at: 1
  updated_at: 2
`
	SetConfiguredRulesPath(writeTempRuleFile(t, content))
	defer SetConfiguredRulesPath("")

	svc := New(nil)
	call := func(query string) map[string]any {
		t.Helper()
		req := httptest.NewRequest("GET", "/d/rules"+query, nil)
		rec := httptest.NewRecorder()
		svc.Rules(rec, req)
		if rec.Code != 200 {
			t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("响应 JSON 解析失败: %v", err)
		}
		return resp.Data
	}

	data := call("")
	if int(data["total"].(float64)) != 2 {
		t.Fatalf("期望 total=2, 实得 %v", data["total"])
	}
	items := data["items"].([]any)
	first := items[0].(map[string]any)
	if first["recommended_action"] != "block_and_report" {
		t.Errorf("JSON 缺少 recommended_action: %v", first)
	}
	ev, _ := first["evidence"].(map[string]any)
	if ev == nil || ev["narrative"] != "建议阻断。" || ev["misp_event_id"] != "2167" {
		t.Errorf("JSON evidence 字段错误: %v", ev)
	}
	second := items[1].(map[string]any)
	if _, has := second["evidence"]; has {
		t.Errorf("无 evidence 的规则不应输出该字段: %v", second)
	}

	// 关键字命中 evidence.threat_labels
	if data := call("?keyword=akira"); int(data["total"].(float64)) != 1 {
		t.Errorf("keyword=akira 期望命中 1 条, 实得 %v", data["total"])
	}
	// 关键字命中 evidence.misp_event_id
	if data := call("?keyword=2167"); int(data["total"].(float64)) != 1 {
		t.Errorf("keyword=2167 期望命中 1 条, 实得 %v", data["total"])
	}
	// 关键字命中 recommended_action
	if data := call("?keyword=monitor"); int(data["total"].(float64)) != 1 {
		t.Errorf("keyword=monitor 期望命中 1 条, 实得 %v", data["total"])
	}
	// 原有 type 过滤不受影响
	if data := call("?type=ip"); int(data["total"].(float64)) != 1 {
		t.Errorf("type=ip 期望命中 1 条, 实得 %v", data["total"])
	}
}

// 真实样例：仓库根 docs/intel.yaml（存在时）应解析出 10 条 domain 规则且证据齐全。
func TestParseRuleFileRealIntelYaml(t *testing.T) {
	p := filepath.Join("..", "..", "..", "..", "docs", "intel.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("docs/intel.yaml 不存在，跳过: %v", err)
	}
	items, err := parseRuleFile(p)
	if err != nil {
		t.Fatalf("解析真实 intel.yaml 失败: %v", err)
	}
	if len(items) != 10 {
		t.Fatalf("期望 10 条规则, 实得 %d", len(items))
	}
	for i := range items {
		it := &items[i]
		if it.ID == "" || it.Type != "domain" || it.Value == "" || !it.Enabled {
			t.Errorf("第 %d 条基础字段异常: %+v", i, it)
		}
		if it.RecommendedAction != "block_and_report" {
			t.Errorf("第 %d 条 recommended_action 异常: %q", i, it.RecommendedAction)
		}
		if it.Evidence == nil || it.Evidence.Activity == "" || len(it.Evidence.ThreatLabels) == 0 {
			t.Errorf("第 %d 条 evidence 缺失: %+v", i, it.Evidence)
		}
		if len(it.Tags) == 0 {
			t.Errorf("第 %d 条 tags 缺失", i)
		}
	}
}
