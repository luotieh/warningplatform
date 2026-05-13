package poc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"vulnscan-backend/knowledge/nuclei"
	"vulnscan-backend/model"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/permission"
	"github.com/gin-gonic/gin"
)

type HandlerPoc struct {
	svc *ServicePoc
}

func NewHandlerPoc(svc *ServicePoc) *HandlerPoc {
	return &HandlerPoc{svc: svc}
}

func (h *HandlerPoc) List(c *gin.Context) {
	query, ok := web.BindQuery[PocQuery](c)
	if !ok {
		return
	}

	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(query, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerPoc) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerPoc) Create(c *gin.Context) {
	req, ok := web.BindJSON[createPocReq](c)
	if !ok {
		return
	}
	item := req.toModel()
	if err := h.svc.Create(item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerPoc) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	updates, ok := web.BindJSON[map[string]any](c)
	if !ok {
		return
	}
	if err := h.svc.Update(uri.Id, updates); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerPoc) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

type toggleReq struct {
	Enabled bool `json:"enabled"`
}

func (h *HandlerPoc) Toggle(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[toggleReq](c)
	if !ok {
		return
	}
	if err := h.svc.Toggle(uri.Id, req.Enabled); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

type importYAMLReq struct {
	YAML string `json:"yaml" binding:"required"`
}

func (h *HandlerPoc) ImportYAML(c *gin.Context) {
	req, ok := web.BindJSON[importYAMLReq](c)
	if !ok {
		return
	}
	item, err := h.svc.ImportYAML(req.YAML)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

type importDirReq struct {
	Dir string `json:"dir" binding:"required"`
}

func (h *HandlerPoc) ImportDir(c *gin.Context) {
	req, ok := web.BindJSON[importDirReq](c)
	if !ok {
		return
	}
	imported, skipped, errors := h.svc.ImportDir(req.Dir)
	web.OK(c).Data(gin.H{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errors,
	}).Send()
}

type createPocReq struct {
	PocID       string   `json:"poc_id"`
	Name        string   `json:"name" binding:"required"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Content     string   `json:"content" binding:"required"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
	CVE         string   `json:"cve"`
}

func (r *createPocReq) toModel() *model.PocTemplate {
	return &model.PocTemplate{
		PocID:       r.PocID,
		Name:        r.Name,
		Severity:    r.Severity,
		Description: r.Description,
		Content:     r.Content,
		Category:    r.Category,
		Tags:        r.Tags,
		CVE:         r.CVE,
		Format:      "yaml",
		Enabled:     true,
		Source:      "manual",
	}
}

type validateReq struct {
	YAML string `json:"yaml" binding:"required"`
}

type validateResult struct {
	Valid       bool     `json:"valid"`
	Error       string   `json:"error,omitempty"`
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Author      string   `json:"author,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reference   []string `json:"reference,omitempty"`
}

func (h *HandlerPoc) Validate(c *gin.Context) {
	req, ok := web.BindJSON[validateReq](c)
	if !ok {
		return
	}

	tmpl, err := nuclei.ParseTemplate([]byte(req.YAML))
	if err != nil {
		web.OK(c).Data(validateResult{Valid: false, Error: err.Error()}).Send()
		return
	}

	var tags []string
	if tmpl.Info.Tags != "" {
		for _, t := range splitTags(tmpl.Info.Tags) {
			tags = append(tags, t)
		}
	}

	web.OK(c).Data(validateResult{
		Valid:       true,
		ID:          tmpl.ID,
		Name:        tmpl.Info.Name,
		Author:      tmpl.Info.Author,
		Severity:    tmpl.Info.Severity,
		Description: tmpl.Info.Description,
		Tags:        tags,
		Reference:   tmpl.Info.Reference,
	}).Send()
}

func splitTags(s string) []string {
	var result []string
	for _, part := range []byte(s) {
		if part == ',' {
			continue
		}
	}
	// split by comma
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			t := trimSpace(s[start:i])
			if t != "" {
				result = append(result, t)
			}
			start = i + 1
		}
	}
	return result
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

type testPocReq struct {
	YAML      string `json:"yaml" binding:"required"`
	TargetURL string `json:"target_url" binding:"required"`
}

type testPocResult struct {
	Success  bool           `json:"success"`
	Error    string         `json:"error,omitempty"`
	Duration string         `json:"duration"`
	Findings []testPocMatch `json:"findings"`
}

type testPocMatch struct {
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	MatchedAt   string `json:"matched_at"`
	MatcherName string `json:"matcher_name,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	CurlCmd     string `json:"curl_command,omitempty"`
}

func (h *HandlerPoc) TestPoc(c *gin.Context) {
	req, ok := web.BindJSON[testPocReq](c)
	if !ok {
		return
	}

	tmpl, err := nuclei.ParseTemplate([]byte(req.YAML))
	if err != nil {
		web.OK(c).Data(testPocResult{
			Success: false,
			Error:   fmt.Sprintf("YAML解析失败: %s", err.Error()),
		}).Send()
		return
	}

	dir, err := os.MkdirTemp("", "poc-test-*")
	if err != nil {
		web.Fail(c).Msg("创建临时目录失败").Send()
		return
	}
	defer os.RemoveAll(dir)

	tmplPath := filepath.Join(dir, tmpl.ID+".yaml")
	if err := os.WriteFile(tmplPath, []byte(req.YAML), 0644); err != nil {
		web.Fail(c).Msg("写入模板失败").Send()
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	start := time.Now()
	var findings []testPocMatch
	var mu sync.Mutex

	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{
			Templates: []string{dir},
		}),
		nucleilib.DisableUpdateCheck(),
		nucleilib.WithNetworkConfig(nucleilib.NetworkConfig{
			Timeout:         15,
			Retries:         1,
			MaxHostError:    5,
			SystemResolvers: true,
		}),
		nucleilib.WithConcurrency(nucleilib.Concurrency{
			TemplateConcurrency: 1,
			HostConcurrency:     1,
		}),
		nucleilib.WithGlobalRateLimit(50, time.Second),
	}

	ne, err := nucleilib.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		web.OK(c).Data(testPocResult{
			Success:  false,
			Error:    fmt.Sprintf("初始化Nuclei引擎失败: %s", err.Error()),
			Duration: time.Since(start).Round(time.Millisecond).String(),
		}).Send()
		return
	}
	defer ne.Close()

	ne.LoadTargets([]string{req.TargetURL}, true)

	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		match := testPocMatch{
			TemplateID:  event.TemplateID,
			Name:        event.Info.Name,
			Severity:    event.Info.SeverityHolder.Severity.String(),
			MatchedAt:   event.Matched,
			MatcherName: event.MatcherName,
			CurlCmd:     event.CURLCommand,
		}
		if event.Request != "" || event.Response != "" {
			evidence := ""
			if event.Request != "" {
				r := event.Request
				if len(r) > 500 {
					r = r[:500] + "..."
				}
				evidence += "--- Request ---\n" + r
			}
			if event.Response != "" {
				r := event.Response
				if len(r) > 1000 {
					r = r[:1000] + "..."
				}
				if evidence != "" {
					evidence += "\n"
				}
				evidence += "--- Response ---\n" + r
			}
			match.Evidence = evidence
		}
		mu.Lock()
		findings = append(findings, match)
		mu.Unlock()
	})

	duration := time.Since(start).Round(time.Millisecond).String()

	if err != nil {
		slog.Warn("[PocTest] 执行出错", "error", err)
	}

	web.OK(c).Data(testPocResult{
		Success:  true,
		Duration: duration,
		Findings: findings,
	}).Send()
}
