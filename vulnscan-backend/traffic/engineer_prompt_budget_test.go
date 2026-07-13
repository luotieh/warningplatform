package traffic

import (
	"strings"
	"testing"
)

// writeJSONSection 对超大列表(如大量自动驾驶命令)必须做体量上限,避免工程师对话
// prompt 撑爆 16K 窗口;截断需保留末尾的「当前工程师问题」不受影响。
func TestWriteJSONSectionCapsHugePayload(t *testing.T) {
	huge := make([]map[string]string, 2000)
	for i := range huge {
		huge[i] = map[string]string{"cmd": "横向移动数据外传载荷下载", "id": "abcdefghij"}
	}
	var b strings.Builder
	writeJSONSection(&b, "## 自动驾驶命令", huge)
	out := b.String()

	if n := len([]rune(out)); n > jsonSectionMaxRunes+64 {
		t.Fatalf("section not capped: %d runes (limit %d)", n, jsonSectionMaxRunes)
	}
	if !strings.Contains(out, "已截断") {
		t.Fatalf("expected truncation marker in capped section")
	}
}

// 正常小体量内容不受影响。
func TestWriteJSONSectionKeepsSmallPayload(t *testing.T) {
	var b strings.Builder
	writeJSONSection(&b, "## 事件总结", []map[string]string{{"summary": "初步研判为探测"}})
	out := b.String()
	if !strings.Contains(out, "初步研判为探测") {
		t.Fatalf("small payload should be intact, got %q", out)
	}
	if strings.Contains(out, "已截断") {
		t.Fatalf("small payload should not be truncated")
	}
}
