package intel

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct {
	matcher *VulnMatcher
	sync    *SyncManager
	db      *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	matcher := NewVulnMatcher()
	subSvc := NewSubscriptionService(db, matcher)
	syncMgr := NewSyncManager(matcher, subSvc)
	return &Handler{
		matcher: matcher,
		sync:    syncMgr,
		db:      db,
	}
}

func (h *Handler) StartSync(ctx context.Context) {
	go h.sync.StartSync(ctx)
}

func (h *Handler) SearchCVE(c *gin.Context) {
	keyword := c.Query("q")
	severity := c.Query("severity")
	hasExploit := c.Query("has_exploit")
	inKEV := c.Query("in_kev")
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "50")
	page, _ := strconv.Atoi(pageStr)
	pageSize, _ := strconv.Atoi(pageSizeStr)
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}

	var filtered []CVEEntry
	for _, cve := range h.matcher.cveDB {
		if keyword != "" {
			kw := strings.ToLower(keyword)
			if !strings.Contains(strings.ToLower(cve.ID), kw) &&
				!strings.Contains(strings.ToLower(cve.Description), kw) {
				continue
			}
		}
		if severity != "" && cve.Severity != severity {
			continue
		}
		if hasExploit == "true" && !cve.HasExploit {
			continue
		}
		if inKEV == "true" && !cve.InKEV {
			continue
		}
		filtered = append(filtered, *cve)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Published.After(filtered[j].Published)
	})

	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	results := filtered[start:end]

	web.OK(c).Data(gin.H{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"results":   results,
	}).Send()
}

func (h *Handler) GetCVE(c *gin.Context) {
	cveID := c.Param("id")
	entry := h.matcher.MatchByCVE(cveID)
	if entry == nil {
		web.Resp(c, web.NotFound)
		return
	}
	web.RespContent(c, web.Success, entry)
}

func (h *Handler) MatchFingerprint(c *gin.Context) {
	product := c.Query("product")
	version := c.Query("version")
	if product == "" {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	matches := h.matcher.MatchByFingerprint(product, version)
	web.OK(c).Data(gin.H{
		"product": product,
		"version": version,
		"matches": matches,
		"count":   len(matches),
	}).Send()
}

func (h *Handler) GetSources(c *gin.Context) {
	sources := h.sync.GetSources()
	web.RespContent(c, web.Success, sources)
}

func (h *Handler) AddSource(c *gin.Context) {
	var req struct {
		Name         string `json:"name" binding:"required"`
		Type         string `json:"type" binding:"required"`
		URL          string `json:"url" binding:"required"`
		SyncInterval string `json:"sync_interval"`
		APIKey       string `json:"api_key"`
		Enabled      bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	source := IntelSource{
		Name:         req.Name,
		Type:         req.Type,
		URL:          req.URL,
		SyncInterval: req.SyncInterval,
		APIKey:       req.APIKey,
		Enabled:      req.Enabled,
		Custom:       true,
	}
	h.sync.AddSource(source)
	web.RespContent(c, web.Success, source)
}

func (h *Handler) UpdateSource(c *gin.Context) {
	name := c.Param("name")

	var req struct {
		URL          *string `json:"url"`
		SyncInterval *string `json:"sync_interval"`
		APIKey       *string `json:"api_key"`
		Enabled      *bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}

	updated := h.sync.UpdateSource(name, func(s *IntelSource) {
		if req.URL != nil {
			s.URL = *req.URL
		}
		if req.SyncInterval != nil {
			s.SyncInterval = *req.SyncInterval
		}
		if req.APIKey != nil {
			s.APIKey = *req.APIKey
		}
		if req.Enabled != nil {
			s.Enabled = *req.Enabled
		}
	})

	if !updated {
		web.Resp(c, web.NotFound)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) DeleteSource(c *gin.Context) {
	name := c.Param("name")
	if !h.sync.DeleteSource(name) {
		web.Resp(c, web.NotFound)
		return
	}
	web.Resp(c, web.Success)
}

func (h *Handler) SyncNow(c *gin.Context) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()
		h.sync.syncOnce(ctx)
	}()
	web.OK(c).Data(gin.H{
		"message": "同步任务已异步触发，后台执行中",
		"sources": h.sync.GetSources(),
	}).Send()
}

func (h *Handler) GetStats(c *gin.Context) {
	total := len(h.matcher.cveDB)
	var critical, high, medium, low, withExploit, inKEV int
	for _, cve := range h.matcher.cveDB {
		switch cve.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
		if cve.HasExploit {
			withExploit++
		}
		if cve.InKEV {
			inKEV++
		}
	}

	web.OK(c).Data(gin.H{
		"total":        total,
		"critical":     critical,
		"high":         high,
		"medium":       medium,
		"low":          low,
		"with_exploit": withExploit,
		"in_kev":       inKEV,
		"sources":      h.sync.GetSources(),
	}).Send()
}

func (h *Handler) AnalyzeAsset(c *gin.Context) {
	assetID := c.Param("asset_id")
	if h.db == nil {
		web.Resp(c, web.InternalError)
		return
	}

	var findings []model.ScanFinding
	h.db.Where("asset_id = ? AND type = ?", assetID, "service").Find(&findings)

	type matchResult struct {
		Product string      `json:"product"`
		Version string      `json:"version"`
		Matches []VulnMatch `json:"matches"`
	}

	var results []matchResult
	totalMatches := 0

	seen := make(map[string]bool)
	for _, f := range findings {
		product := f.Title
		version := ""
		if f.Data != nil {
			if v, ok := f.Data["version"]; ok {
				version, _ = v.(string)
			}
			if p, ok := f.Data["product"]; ok {
				if ps, ok2 := p.(string); ok2 && ps != "" {
					product = ps
				}
			}
		}
		if product == "" {
			continue
		}
		key := product + "|" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		matches := h.matcher.MatchByFingerprint(product, version)
		if len(matches) > 0 {
			results = append(results, matchResult{
				Product: product,
				Version: version,
				Matches: matches,
			})
			totalMatches += len(matches)
		}
	}

	web.OK(c).Data(gin.H{
		"asset_id":     assetID,
		"services":     len(findings),
		"matched_cves": totalMatches,
		"results":      results,
	}).Send()
}

func (h *Handler) TrendAnalysis(c *gin.Context) {
	dimension := c.DefaultQuery("dimension", "time")

	switch dimension {
	case "time":
		monthMap := make(map[string]int)
		for _, cve := range h.matcher.cveDB {
			if cve.Published.IsZero() {
				continue
			}
			key := cve.Published.Format("2006-01")
			monthMap[key]++
		}
		type monthEntry struct {
			Month string `json:"month"`
			Count int    `json:"count"`
		}
		var entries []monthEntry
		for k, v := range monthMap {
			entries = append(entries, monthEntry{Month: k, Count: v})
		}
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[j].Month < entries[i].Month {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}
		if len(entries) > 24 {
			entries = entries[len(entries)-24:]
		}
		web.OK(c).Data(gin.H{"dimension": "time", "data": entries}).Send()

	case "severity":
		severityMap := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		for _, cve := range h.matcher.cveDB {
			if cve.Severity != "" {
				severityMap[cve.Severity]++
			}
		}
		type sevEntry struct {
			Severity string `json:"severity"`
			Count    int    `json:"count"`
		}
		entries := []sevEntry{
			{Severity: "critical", Count: severityMap["critical"]},
			{Severity: "high", Count: severityMap["high"]},
			{Severity: "medium", Count: severityMap["medium"]},
			{Severity: "low", Count: severityMap["low"]},
		}
		web.OK(c).Data(gin.H{"dimension": "severity", "data": entries}).Send()

	case "product":
		productMap := make(map[string]int)
		for _, cve := range h.matcher.cveDB {
			for _, cpe := range cve.CPE {
				parts := strings.Split(cpe, ":")
				if len(parts) >= 5 {
					product := parts[4]
					if product != "*" && product != "" {
						productMap[product]++
					}
				}
			}
		}
		type prodEntry struct {
			Product string `json:"product"`
			Count   int    `json:"count"`
		}
		var entries []prodEntry
		for k, v := range productMap {
			entries = append(entries, prodEntry{Product: k, Count: v})
		}
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[j].Count > entries[i].Count {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}
		if len(entries) > 20 {
			entries = entries[:20]
		}
		web.OK(c).Data(gin.H{"dimension": "product", "data": entries}).Send()

	case "exploit":
		exploitTypeMap := make(map[string]int)
		impactMap := make(map[string]int)
		for _, cve := range h.matcher.cveDB {
			if cve.HasExploit {
				if cve.ExploitType != "" {
					exploitTypeMap[cve.ExploitType]++
				}
				if cve.Impact != "" {
					impactMap[cve.Impact]++
				}
			}
		}
		web.OK(c).Data(gin.H{
			"dimension":     "exploit",
			"exploit_types": exploitTypeMap,
			"impacts":       impactMap,
		}).Send()

	default:
		web.Resp(c, web.ParamsMissingRequired)
	}
}

func (h *Handler) TopEPSS(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "20")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	type scored struct {
		CVE  CVEEntry `json:"cve"`
		EPSS float64  `json:"epss"`
	}
	var all []scored
	for _, cve := range h.matcher.cveDB {
		if cve.EPSSScore > 0 {
			all = append(all, scored{CVE: *cve, EPSS: cve.EPSSScore})
		}
	}

	for i := 0; i < len(all)-1; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].EPSS > all[i].EPSS {
				all[i], all[j] = all[j], all[i]
			}
		}
	}

	if len(all) > limit {
		all = all[:limit]
	}

	web.OK(c).Data(gin.H{
		"total":   len(all),
		"results": all,
	}).Send()
}

func (h *Handler) BatchAnalyze(c *gin.Context) {
	if h.db == nil {
		web.Resp(c, web.InternalError)
		return
	}

	var req struct {
		AssetIDs []string `json:"asset_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.AssetIDs) == 0 {
		web.Resp(c, web.ParamsMissingRequired)
		return
	}
	if len(req.AssetIDs) > 100 {
		req.AssetIDs = req.AssetIDs[:100]
	}

	var findings []model.ScanFinding
	h.db.Where("asset_id IN ? AND type = ?", req.AssetIDs, "service").Find(&findings)

	assetFindings := make(map[string][]model.ScanFinding)
	for _, f := range findings {
		assetFindings[f.AssetID] = append(assetFindings[f.AssetID], f)
	}

	type assetAnalysis struct {
		AssetID  string `json:"asset_id"`
		Services int    `json:"services"`
		CVECount int    `json:"cve_count"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
	}

	var analyses []assetAnalysis
	for _, assetID := range req.AssetIDs {
		afs := assetFindings[assetID]
		analysis := assetAnalysis{AssetID: assetID, Services: len(afs)}

		seen := make(map[string]bool)
		for _, f := range afs {
			product := f.Title
			version := ""
			if f.Data != nil {
				if v, ok := f.Data["version"]; ok {
					version, _ = v.(string)
				}
				if p, ok := f.Data["product"]; ok {
					if ps, ok2 := p.(string); ok2 && ps != "" {
						product = ps
					}
				}
			}
			if product == "" || seen[product+"|"+version] {
				continue
			}
			seen[product+"|"+version] = true

			matches := h.matcher.MatchByFingerprint(product, version)
			for _, m := range matches {
				analysis.CVECount++
				switch m.CVE.Severity {
				case "critical":
					analysis.Critical++
				case "high":
					analysis.High++
				}
			}
		}
		analyses = append(analyses, analysis)
	}

	web.OK(c).Data(gin.H{
		"analyzed": len(analyses),
		"results":  analyses,
	}).Send()
}
