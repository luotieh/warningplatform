package service

import (
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

// 对话证据注入研判报告：分析师补充证据与模型结论进入 prompt，专家工作流消息不参与。
func TestDialogueEvidenceSection(t *testing.T) {
	svc := Services{Store: store.NewMemoryStore()}
	if _, err := svc.Store.CreateEvent(domain.Event{EventID: "e1", EventName: "测试事件", Severity: "high", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	if got := svc.dialogueEvidenceSection("e1"); got != "无" {
		t.Fatalf("no dialogue must fall back to 无, got %q", got)
	}
	if _, err := svc.Store.AddMessage(domain.Message{
		EventID: "e1", MessageFrom: domain.RoleUser, MessageCategory: "engineer_chat",
		MessageContent: "补充证据：该主机为内部测试服务器，无外网业务",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Store.AddMessage(domain.Message{
		EventID: "e1", MessageFrom: domain.RoleAssistant, MessageCategory: "engineer_chat",
		MessageContent: EvidenceReplyContent("结合补充证据，威胁事件概率下修为 20%", "{}"),
	}); err != nil {
		t.Fatal(err)
	}
	// 专家工作流消息不属于对话证据，不得注入。
	if _, err := svc.Store.AddMessage(domain.Message{
		EventID: "e1", MessageFrom: domain.RoleExpert, MessageCategory: "agent",
		MessageContent: "不应出现在对话补充中",
	}); err != nil {
		t.Fatal(err)
	}

	got := svc.dialogueEvidenceSection("e1")
	if !strings.Contains(got, "内部测试服务器") {
		t.Fatalf("analyst evidence missing: %q", got)
	}
	if !strings.Contains(got, "威胁事件概率下修为 20%") {
		t.Fatalf("assistant reply missing: %q", got)
	}
	if strings.Contains(got, "不应出现在对话补充中") {
		t.Fatalf("workflow message leaked into dialogue section: %q", got)
	}

	p := autoAnalysisPromptWithDialogue(domain.Event{EventID: "e1"}, "", got)
	if !strings.Contains(p, "分析师对话补充") || !strings.Contains(p, "内部测试服务器") {
		t.Fatal("prompt missing dialogue section")
	}
	if est := estimateTokens(p); est > promptBudgetTokens {
		t.Fatalf("prompt over budget: %d", est)
	}
}
