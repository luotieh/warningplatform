package sitemonitor

import (
	"io"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

// ══ 词库 ══

func (h *HandlerMonitor) ListWordLibraries(c *gin.Context) {
	req, ok := web.BindQuery[contract.WordLibraryListReq](c)
	if !ok {
		return
	}
	total, list, err := h.svc.ListWordLibraries(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, list).Send()
}

func (h *HandlerMonitor) CreateWordLibrary(c *gin.Context) {
	var dto struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if !web.ValidationJson(c, &dto) {
		return
	}
	lib := &model.MonitorWordLibrary{}
	lib.Name = dto.Name
	lib.Description = dto.Description
	if err := h.svc.CreateWordLibrary(c.Request.Context(), lib); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"id": lib.ID}).Send()
}

func (h *HandlerMonitor) GetWordLibrary(c *gin.Context) {
	id := c.Param("id")
	detail, err := h.svc.GetWordLibrary(c.Request.Context(), id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(detail).Send()
}

func (h *HandlerMonitor) UpdateWordLibrary(c *gin.Context) {
	id := c.Param("id")
	var req contract.WordLibraryUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateWordLibrary(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) DeleteWordLibrary(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteWordLibrary(c.Request.Context(), id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ══ 词库分类 ══

func (h *HandlerMonitor) ListWordCategories(c *gin.Context) {
	id := c.Param("id")
	cats, err := h.svc.ListWordCategories(c.Request.Context(), id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(cats).Send()
}

func (h *HandlerMonitor) CreateWordCategory(c *gin.Context) {
	var dto struct {
		LibraryID   string `json:"library_id" binding:"required"`
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if !web.ValidationJson(c, &dto) {
		return
	}
	cat := &model.MonitorWordCategory{}
	cat.LibraryID = dto.LibraryID
	cat.Name = dto.Name
	cat.Description = dto.Description
	if err := h.svc.CreateWordCategory(c.Request.Context(), cat); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"id": cat.ID}).Send()
}

func (h *HandlerMonitor) UpdateWordCategory(c *gin.Context) {
	id := c.Param("id")
	var req contract.WordCategoryUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateWordCategory(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) DeleteWordCategory(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteWordCategory(c.Request.Context(), id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ══ 词条 ══

func (h *HandlerMonitor) ListWordEntries(c *gin.Context) {
	req, ok := web.BindQuery[contract.WordEntryListReq](c)
	if !ok {
		return
	}
	total, list, err := h.svc.ListWordEntries(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, list).Send()
}

func (h *HandlerMonitor) BatchCreateWordEntries(c *gin.Context) {
	var dtos []struct {
		CategoryID string `json:"category_id" binding:"required"`
		Word       string `json:"word" binding:"required"`
		Severity   string `json:"severity"`
	}
	if !web.ValidationJson(c, &dtos) {
		return
	}
	entries := make([]model.MonitorWordEntry, len(dtos))
	for i, d := range dtos {
		sev := d.Severity
		if sev == "" {
			sev = "medium"
		}
		entries[i] = model.MonitorWordEntry{
			CategoryID: d.CategoryID,
			Word:       d.Word,
			Severity:   sev,
		}
	}
	if err := h.svc.BatchCreateWordEntries(c.Request.Context(), entries); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) ImportWordEntries(c *gin.Context) {
	categoryID := c.PostForm("category_id")
	severity := c.PostForm("severity")
	if categoryID == "" {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}
	if severity == "" {
		severity = "medium"
	}

	file, err := c.FormFile("file")
	if err != nil {
		web.Err(c, web.ParamsMissingRequired).Send()
		return
	}

	f, err := file.Open()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 10*1024*1024))
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	content := string(data)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	var words []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		word := strings.TrimSpace(parts[0])
		if word != "" {
			words = append(words, word)
		}
	}

	if len(words) == 0 {
		web.OK(c).Data(gin.H{"imported": 0, "message": "文件中未发现有效词条"}).Send()
		return
	}

	seen := make(map[string]bool)
	var entries []model.MonitorWordEntry
	for _, w := range words {
		lw := strings.ToLower(w)
		if seen[lw] {
			continue
		}
		seen[lw] = true
		entries = append(entries, model.MonitorWordEntry{
			CategoryID: categoryID,
			Word:       w,
			Severity:   severity,
		})
	}

	if err := h.svc.BatchCreateWordEntries(c.Request.Context(), entries); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	web.OK(c).Data(gin.H{
		"imported":   len(entries),
		"duplicated": len(words) - len(entries),
	}).Send()
}

func (h *HandlerMonitor) DeleteWordEntries(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.DeleteWordEntries(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ══ 文件库 ══

func (h *HandlerMonitor) ListFileLibraries(c *gin.Context) {
	req, ok := web.BindQuery[contract.FileLibraryListReq](c)
	if !ok {
		return
	}
	total, list, err := h.svc.ListFileLibraries(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, list).Send()
}

func (h *HandlerMonitor) CreateFileLibrary(c *gin.Context) {
	var dto struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if !web.ValidationJson(c, &dto) {
		return
	}
	lib := &model.MonitorFileLibrary{}
	lib.Name = dto.Name
	lib.Description = dto.Description
	if err := h.svc.CreateFileLibrary(c.Request.Context(), lib); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{"id": lib.ID}).Send()
}

func (h *HandlerMonitor) GetFileLibrary(c *gin.Context) {
	id := c.Param("id")
	detail, err := h.svc.GetFileLibrary(c.Request.Context(), id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(detail).Send()
}

func (h *HandlerMonitor) UpdateFileLibrary(c *gin.Context) {
	id := c.Param("id")
	var req contract.FileLibraryUpdateReq
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateFileLibrary(c.Request.Context(), id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) DeleteFileLibrary(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteFileLibrary(c.Request.Context(), id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

// ══ 文件条目 ══

func (h *HandlerMonitor) ListFileEntries(c *gin.Context) {
	req, ok := web.BindQuery[contract.FileEntryListReq](c)
	if !ok {
		return
	}
	total, list, err := h.svc.ListFileEntries(c.Request.Context(), req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, list).Send()
}

func (h *HandlerMonitor) BatchCreateFileEntries(c *gin.Context) {
	var dtos []struct {
		LibraryID string `json:"library_id" binding:"required"`
		Path      string `json:"path" binding:"required"`
		Mark      string `json:"mark"`
		Risk      string `json:"risk"`
	}
	if !web.ValidationJson(c, &dtos) {
		return
	}
	entries := make([]model.MonitorFileEntry, len(dtos))
	for i, d := range dtos {
		risk := d.Risk
		if risk == "" {
			risk = "high"
		}
		entries[i] = model.MonitorFileEntry{
			LibraryID: d.LibraryID,
			Path:      d.Path,
			Mark:      d.Mark,
			Risk:      risk,
		}
	}
	if err := h.svc.BatchCreateFileEntries(c.Request.Context(), entries); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) DeleteFileEntries(c *gin.Context) {
	var req struct {
		IDs []int64 `json:"ids" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.DeleteFileEntries(c.Request.Context(), req.IDs); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerMonitor) ImportFileEntries(c *gin.Context) {
	libraryID := c.PostForm("library_id")
	risk := c.PostForm("risk")
	if libraryID == "" {
		web.Fail(c).Msg("library_id 必填").Send()
		return
	}
	if risk == "" {
		risk = "high"
	}

	file, _, err := c.Request.FormFile("file")
	if err != nil {
		web.Fail(c).Msg("请上传文件").Send()
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		web.Fail(c).Msg("读取文件失败").Send()
		return
	}

	lines := strings.Split(string(raw), "\n")
	seen := make(map[string]bool)
	var entries []model.MonitorFileEntry
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		path := strings.TrimSpace(parts[0])
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true

		mark := ""
		entryRisk := risk
		if len(parts) >= 2 {
			mark = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			entryRisk = strings.TrimSpace(parts[2])
		}

		entries = append(entries, model.MonitorFileEntry{
			LibraryID: libraryID,
			Path:      path,
			Mark:      mark,
			Risk:      entryRisk,
		})
	}

	if len(entries) == 0 {
		web.OK(c).Data(gin.H{"imported": 0, "message": "文件中未发现有效路径"}).Send()
		return
	}

	duplicated := 0
	var toCreate []model.MonitorFileEntry
	for _, e := range entries {
		var count int64
		h.svc.CountFileEntryByPath(c.Request.Context(), e.LibraryID, e.Path, &count)
		if count > 0 {
			duplicated++
			continue
		}
		toCreate = append(toCreate, e)
	}

	if len(toCreate) > 0 {
		if err := h.svc.BatchCreateFileEntries(c.Request.Context(), toCreate); err != nil {
			web.Fail(c).Err(err).Send()
			return
		}
	}

	web.OK(c).Data(gin.H{
		"imported":   len(toCreate),
		"duplicated": duplicated,
		"total":      len(entries),
	}).Send()
}

// ══ 默认配置 ══

func (h *HandlerMonitor) ListDefaultConfigs(c *gin.Context) {
	configs, err := h.svc.ListDefaultConfigs(c.Request.Context())
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(configs).Send()
}

func (h *HandlerMonitor) GetDefaultConfig(c *gin.Context) {
	dimension := c.Param("dimension")
	cfg, err := h.svc.GetDefaultConfig(c.Request.Context(), dimension)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(cfg).Send()
}

func (h *HandlerMonitor) UpdateDefaultConfig(c *gin.Context) {
	dimension := c.Param("dimension")
	var req struct {
		ConfigJSON map[string]any `json:"config_json" binding:"required"`
	}
	if !web.ValidationJson(c, &req) {
		return
	}
	if err := h.svc.UpdateDefaultConfig(c.Request.Context(), dimension, req.ConfigJSON); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
