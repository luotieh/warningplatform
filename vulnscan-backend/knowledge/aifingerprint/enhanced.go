package aifingerprint

import (
	"context"
	"fmt"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
)

// EnhancedService 带有 RAG 增强的 AI 指纹识别服务。
type EnhancedService struct {
	*Service
	rag *RAGStore
}

// NewEnhancedService 创建 RAG 增强的 AI 指纹识别服务。
func NewEnhancedService(aiSvc ai.Service, model string) *EnhancedService {
	return &EnhancedService{
		Service: NewService(aiSvc, model),
		rag:     NewRAGStore(),
	}
}

// AnalyzeFingerprintRAG 通过 RAG 检索增强 + LLM 分析，识别指纹。
// 先从知识库检索相似指纹作为参考，再让 LLM 做最终判断。
func (s *EnhancedService) AnalyzeFingerprintRAG(ctx context.Context, rawData map[string]string) ([]FingerprintResult, error) {
	if s.ai == nil {
		return nil, fmt.Errorf("AI service not configured")
	}

	// 1) 构建查询文本
	var queryParts []string
	for _, v := range rawData {
		queryParts = append(queryParts, v)
	}
	queryText := strings.Join(queryParts, " ")

	// 2) RAG 检索相关的已知指纹
	references := s.rag.Search(ctx, queryText, 5)

	// 3) 构建增强 prompt
	prompt := buildRAGFingerprintPrompt(rawData, references)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := s.ai.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: s.model,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: fingerprintSystemPrompt},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.1,
		MaxTokens:   1024,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("empty LLM response")
	}

	content := resp.Choices[0].Message.Content
	results, err := parseFingerprintResponse(content)
	if err != nil {
		return nil, err
	}

	// 4) 将高置信度的新发现反馈到知识库（持续学习）
	for _, r := range results {
		if r.Confidence >= 80 && !s.isKnownProduct(r.Product) {
			s.rag.AddEntry(RAGEntry{
				ID:       strings.ToLower(strings.ReplaceAll(r.Product, " ", "_")),
				Product:  r.Product,
				Vendor:   r.Vendor,
				Category: r.Category,
				Patterns: []string{r.Evidence},
			})
		}
	}

	return results, nil
}

// LearnFromResult 手动将确认的指纹结果加入知识库。
func (s *EnhancedService) LearnFromResult(result FingerprintResult, patterns []string) {
	s.rag.AddEntry(RAGEntry{
		ID:       strings.ToLower(strings.ReplaceAll(result.Product, " ", "_")),
		Product:  result.Product,
		Vendor:   result.Vendor,
		Category: result.Category,
		Patterns: patterns,
	})
}

// KnowledgeCount 返回当前知识库条目总数。
func (s *EnhancedService) KnowledgeCount() int {
	return s.rag.Count()
}

func (s *EnhancedService) isKnownProduct(product string) bool {
	results := s.rag.Search(context.Background(), product, 1)
	if len(results) > 0 && strings.EqualFold(results[0].Product, product) {
		return true
	}
	return false
}

func buildRAGFingerprintPrompt(rawData map[string]string, refs []RAGEntry) string {
	var sb strings.Builder
	sb.WriteString("请分析以下原始网络数据，提取设备/软件指纹。\n\n")

	if len(refs) > 0 {
		sb.WriteString("## 参考已知指纹（供参考，不必拘泥于此）\n\n")
		for _, ref := range refs {
			sb.WriteString(fmt.Sprintf("- %s (%s/%s): 特征 %v\n",
				ref.Product, ref.Vendor, ref.Category, ref.Patterns))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 待分析数据\n\n")
	for key, val := range rawData {
		if len(val) > 2000 {
			val = val[:2000] + "...(truncated)"
		}
		sb.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", key, val))
	}

	sb.WriteString("请识别所有可能的软件/设备指纹，包括但不限于已知指纹库中的产品。")
	sb.WriteString("特别注意可能存在的国产化、自研或定制化软件。")
	return sb.String()
}
