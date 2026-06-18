package sitemonitor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/generate/ulid"
	"github.com/xuri/excelize/v2"
	"gorm.io/gorm"
)

func (s *serviceMonitor) GenerateImportTemplate(_ context.Context) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	sheet := "监测导入"
	f.SetSheetName("Sheet1", sheet)

	headers := []string{
		"名称", "目标类型", "目标值", "请求Host", "监测URL", "协议",
		"可用性", "域名劫持", "篡改", "敏感词", "敏感文件", "暗链",
	}
	descriptions := []string{
		"可选，留空自动取域名",
		"domain 或 ip，留空自动识别",
		"域名或IP，填URL时可留空",
		"仅IP目标必填，如 www.example.com",
		"完整URL、域名或路径；无协议前缀时可配合「协议」列",
		"http/https，留空则自动探测",
		"留空=启用，填\"关闭\"=不启用",
		"同左",
		"同左",
		"同左",
		"同左",
		"同左",
	}
	examples := []string{
		"HTTPS 示例",
		"",
		"",
		"",
		"www.example.com",
		"https",
		"",
		"",
		"",
		"",
		"",
		"",
	}
	examplesHTTP := []string{
		"HTTP 示例",
		"",
		"",
		"",
		"legacy.example.com",
		"http",
		"",
		"",
		"",
		"",
		"",
		"",
	}

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 11, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"4472C4"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border: []excelize.Border{
			{Type: "bottom", Color: "2F5597", Style: 2},
		},
	})
	descStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Size: 9, Color: "808080", Italic: true},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"F2F2F2"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
	})
	exampleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Size: 10, Color: "2E75B6"},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"DEEBF7"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	colWidths := []float64{16, 14, 22, 24, 32, 10, 10, 10, 10, 10, 10, 10}
	for i, w := range colWidths {
		colName, _ := excelize.ColumnNumberToName(i + 1)
		f.SetColWidth(sheet, colName, colName, w)
	}

	for i, h := range headers {
		c, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, c, h)
		f.SetCellStyle(sheet, c, c, headerStyle)
	}
	for i, d := range descriptions {
		c, _ := excelize.CoordinatesToCellName(i+1, 2)
		f.SetCellValue(sheet, c, d)
		f.SetCellStyle(sheet, c, c, descStyle)
	}
	for i, e := range examples {
		c, _ := excelize.CoordinatesToCellName(i+1, 3)
		f.SetCellValue(sheet, c, e)
		f.SetCellStyle(sheet, c, c, exampleStyle)
	}
	for i, e := range examplesHTTP {
		c, _ := excelize.CoordinatesToCellName(i+1, 4)
		f.SetCellValue(sheet, c, e)
		f.SetCellStyle(sheet, c, c, exampleStyle)
	}

	f.SetRowHeight(sheet, 1, 28)
	f.SetRowHeight(sheet, 2, 36)
	f.SetRowHeight(sheet, 3, 22)
	f.SetRowHeight(sheet, 4, 22)

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, fmt.Errorf("生成模板失败: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *serviceMonitor) ImportTasks(ctx context.Context, fileData []byte) (*contract.ImportResult, error) {
	f, err := excelize.OpenReader(bytes.NewReader(fileData))
	if err != nil {
		return nil, fmt.Errorf("Excel解析失败: %w", err)
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("Excel无Sheet页")
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, fmt.Errorf("读取行数据失败: %w", err)
	}

	dataRows := filterDataRows(rows)
	if len(dataRows) == 0 {
		return nil, fmt.Errorf("无有效数据行")
	}

	result := &contract.ImportResult{
		ID:        ulid.GenerateID(),
		Status:    contract.ImportStatusPending,
		Total:     len(dataRows),
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	s.importMu.Lock()
	s.importResults[result.ID] = result
	s.importMu.Unlock()

	useSchemeColumn := importUsesSchemeColumn(rows)

	go s.runImportAsync(result, dataRows, useSchemeColumn)

	return result, nil
}

func filterDataRows(rows [][]string) []importDataRow {
	var dataRows []importDataRow
	for i, row := range rows {
		if i == 0 || isTemplateHelperRow(row) {
			continue
		}
		allEmpty := true
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			continue
		}
		dataRows = append(dataRows, importDataRow{rowIndex: i + 1, cells: row})
	}
	return dataRows
}

type importDataRow struct {
	rowIndex int
	cells    []string
}

type parsedImportRow struct {
	dataRow       importDataRow
	name          string
	targetType    string
	targetValue   string
	virtualHost   string
	defaultScheme string
	pathOrURL     string
	dimStart      int
	err           string
}

func (s *serviceMonitor) runImportAsync(result *contract.ImportResult, dataRows []importDataRow, useSchemeColumn bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Import] panic recovered", "importId", result.ID, "panic", r)
			s.importMu.Lock()
			result.Status = contract.ImportStatusFailed
			s.importMu.Unlock()
		}
	}()

	ctx := context.Background()
	startTime := time.Now()

	s.importMu.Lock()
	result.Status = contract.ImportStatusRunning
	s.importMu.Unlock()

	defaults, _ := s.loadDefaultConfigs(ctx)
	defaults = mergeWithSeeds(defaults)

	// ── Phase 1: 解析所有行，识别需要探测协议的 URL ──
	parsed := make([]parsedImportRow, len(dataRows))
	var needProbe []int

	for i, dr := range dataRows {
		row := dr.cells
		p := parsedImportRow{dataRow: dr, dimStart: 5}

		p.name = cell(row, 0)
		p.targetType = strings.ToLower(cell(row, 1))
		p.targetValue = cell(row, 2)
		p.virtualHost = cell(row, 3)
		p.pathOrURL = cell(row, 4)
		if p.pathOrURL == "" {
			p.pathOrURL = "/"
		}

		p.defaultScheme = "https"
		schemeSpecified := false
		if useSchemeColumn {
			if scheme := normalizeImportScheme(cell(row, 5)); scheme != "" {
				p.defaultScheme = scheme
				schemeSpecified = true
			}
			p.dimStart = 6
		}

		if pr, ok := parseImportMonitorURL(p.pathOrURL, p.defaultScheme); ok {
			if p.targetType == "" {
				p.targetType = pr.targetType
			}
			if p.targetValue == "" {
				p.targetValue = pr.targetValue
			}
			if p.virtualHost == "" {
				p.virtualHost = pr.virtualHost
			}
			if pr.scheme != "" {
				p.defaultScheme = pr.scheme
			}
			if pr.urlOverride != "" {
				p.pathOrURL = pr.urlOverride
			} else if pr.path != "" {
				p.pathOrURL = pr.path
			}
		}

		if p.targetValue == "" {
			p.err = "目标值为空"
		} else if p.name == "" {
			p.name = p.targetValue
		}

		if !schemeSpecified && p.err == "" && !strings.Contains(p.pathOrURL, "://") && p.pathOrURL != "" && p.pathOrURL != "/" {
			needProbe = append(needProbe, i)
		}

		parsed[i] = p
	}

	// ── Phase 2: 并发协议探测（限制 20 并发） ──
	if len(needProbe) > 0 {
		slog.Info("[Import] 开始协议探测", "count", len(needProbe))
		probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Minute)
		defer probeCancel()

		probeConcurrency := runtime.NumCPU() * 10
		if probeConcurrency < 20 {
			probeConcurrency = 20
		}
		if probeConcurrency > 200 {
			probeConcurrency = 200
		}
		slog.Info("[Import] 协议探测并发", "concurrency", probeConcurrency)
		sem := make(chan struct{}, probeConcurrency)
		var wg sync.WaitGroup

		for _, idx := range needProbe {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				if detected := detectImportScheme(probeCtx, parsed[i].pathOrURL); detected != "" {
					parsed[i].defaultScheme = detected
				}
				if pr, ok := parseImportMonitorURL(parsed[i].pathOrURL, parsed[i].defaultScheme); ok {
					if pr.urlOverride != "" {
						parsed[i].pathOrURL = pr.urlOverride
					}
				}
			}(idx)
		}
		wg.Wait()
		slog.Info("[Import] 协议探测完成", "elapsed", time.Since(startTime))
	}

	// ── Phase 3: 去重检查 & 批量数据库写入 ──
	session := s.session().WithContext(ctx)

	existingTargets := s.buildExistingTargetIndex(session)
	existingTasks := s.buildExistingTaskIndex(session)
	assetIndex := s.buildAssetIndex(session)

	const batchSize = 100
	for batchStart := 0; batchStart < len(parsed); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(parsed) {
			batchEnd = len(parsed)
		}
		batch := parsed[batchStart:batchEnd]

		var targets []*model.MonitorTarget
		var pathTasks []*model.MonitorPathTask
		rowResults := make([]contract.ImportRowResult, len(batch))

		for i, p := range batch {
			rr := contract.ImportRowResult{Row: p.dataRow.rowIndex, Name: p.name, URL: p.pathOrURL}
			if p.err != "" {
				rr.Error = p.err
				rowResults[i] = rr
				continue
			}

			taskURL := p.pathOrURL
			if !strings.Contains(taskURL, "://") {
				taskURL = p.defaultScheme + "://" + p.targetValue + p.pathOrURL
			}
			taskKey := strings.ToLower(p.targetValue + "|" + taskURL)
			if _, dup := existingTasks[taskKey]; dup {
				rr.Error = "该监测任务已存在，已跳过"
				rowResults[i] = rr
				continue
			}

			var targetID string
			if existing, ok := existingTargets[strings.ToLower(p.targetValue)]; ok {
				targetID = existing.ID
			} else {
				target := &model.MonitorTarget{
					Name:          p.name,
					TargetType:    p.targetType,
					TargetValue:   p.targetValue,
					DefaultScheme: p.defaultScheme,
					VirtualHost:   p.virtualHost,
					Enabled:       true,
				}
				target.ID = ulid.GenerateID()

				if assetID, found := assetIndex[strings.ToLower(p.targetValue)]; found {
					target.AssetID = assetID
				}

				row := p.dataRow.cells
				for _, dc := range []struct {
					offset int
					dim    string
				}{
					{1, "domain_hijack"}, {4, "sensitive_file"},
				} {
					enabled := cell(row, p.dimStart+dc.offset) != "关闭"
					cfg := map[string]any{"enabled": enabled}
					if defCfg, ok := defaults[dc.dim]; ok {
						for k, v := range defCfg {
							if k != "enabled" {
								cfg[k] = v
							}
						}
					}
					target.SetDimensionConfig(dc.dim, cfg)
				}
				if targetHasScheduledDimensions(target) {
					target.ScheduleEnabled = true
				}

				targets = append(targets, target)
				targetID = target.ID
				existingTargets[strings.ToLower(p.targetValue)] = target
			}

			pt := &model.MonitorPathTask{
				TargetID: targetID,
				Name:     p.name,
				Enabled:  true,
			}
			pt.ID = ulid.GenerateID()
			if strings.Contains(p.pathOrURL, "://") {
				pt.URLOverride = p.pathOrURL
			} else {
				pt.Path = p.pathOrURL
			}

			if assetID, found := assetIndex[strings.ToLower(p.targetValue)]; found {
				pt.AssetID = assetID
			}

			row := p.dataRow.cells
			for _, dc := range []struct {
				offset int
				dim    string
			}{
				{0, "availability"}, {2, "tamper"},
				{3, "sensitive_word"}, {5, "blacklink"},
			} {
				enabled := cell(row, p.dimStart+dc.offset) != "关闭"
				cfg := map[string]any{"enabled": enabled}
				if defCfg, ok := defaults[dc.dim]; ok {
					for k, v := range defCfg {
						if k != "enabled" {
							cfg[k] = v
						}
					}
				}
				pt.SetDimensionConfig(dc.dim, cfg)
			}
			seedPathTaskDefaults(pt)

			pathTasks = append(pathTasks, pt)
			existingTasks[taskKey] = true
			rr.Success = true
			rr.TargetID = targetID
			rr.TaskID = pt.ID
			rowResults[i] = rr
		}

		if len(targets) > 0 {
			if err := session.CreateInBatches(targets, batchSize).Error; err != nil {
				slog.Error("[Import] 批量创建目标失败", "error", err)
				for i := range rowResults {
					if rowResults[i].Success {
						rowResults[i].Success = false
						rowResults[i].Error = "批量创建目标失败: " + err.Error()
						rowResults[i].TaskID = ""
					}
				}
				pathTasks = nil
			}
		}

		if len(pathTasks) > 0 {
			if err := session.CreateInBatches(pathTasks, batchSize).Error; err != nil {
				slog.Error("[Import] 批量创建路径任务失败", "error", err)
				for i := range rowResults {
					if rowResults[i].Success {
						rowResults[i].Success = false
						rowResults[i].Error = "批量创建路径任务失败: " + err.Error()
						rowResults[i].TaskID = ""
					}
				}
			}
		}

		s.importMu.Lock()
		for _, rr := range rowResults {
			if rr.Success {
				result.Success++
			} else {
				result.Failed++
			}
			result.Processed++
			result.Results = append(result.Results, rr)
		}
		s.importMu.Unlock()
	}

	s.importMu.Lock()
	result.Status = contract.ImportStatusCompleted
	s.importMu.Unlock()

	slog.Info("[Import] 导入完成",
		"total", result.Processed,
		"success", result.Success,
		"failed", result.Failed,
		"elapsed", time.Since(startTime),
	)

	if s.onImportDone != nil {
		s.onImportDone(result)
	}
}

func (s *serviceMonitor) updateImportProgress(result *contract.ImportResult, rowResult contract.ImportRowResult, success bool, _ string) {
	s.importMu.Lock()
	defer s.importMu.Unlock()
	if success {
		result.Success++
	} else {
		result.Failed++
	}
	result.Processed++
	result.Results = append(result.Results, rowResult)
}

type importURLParts struct {
	targetType  string
	targetValue string
	virtualHost string
	scheme      string
	path        string
	urlOverride string
}

func importUsesSchemeColumn(rows [][]string) bool {
	if len(rows) == 0 {
		return false
	}
	for _, h := range rows[0] {
		if strings.Contains(strings.TrimSpace(h), "协议") {
			return true
		}
	}
	return false
}

func detectImportScheme(ctx context.Context, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "/") {
		return ""
	}
	hostPart := raw
	path := "/"
	if idx := strings.Index(raw, "/"); idx >= 0 {
		hostPart = raw[:idx]
		path = raw[idx:]
		if path == "" {
			path = "/"
		}
	}
	if hostPart == "" {
		return ""
	}

	httpsURL := "https://" + hostPart + path
	httpURL := "http://" + hostPart + path
	if importURLReachable(ctx, httpsURL) {
		return "https"
	}
	if importURLReachable(ctx, httpURL) {
		return "http"
	}
	return ""
}

func importURLReachable(ctx context.Context, rawURL string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode > 0 && resp.StatusCode < 500 {
			return true
		}
	}
	return false
}

func normalizeImportScheme(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "http", "https":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

// parseImportMonitorURL 解析监测 URL，支持省略 http/https 的写法（如 www.example.com/path）。
func parseImportMonitorURL(raw string, defaultScheme string) (*importURLParts, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "/" {
		return nil, false
	}
	if strings.HasPrefix(raw, "/") {
		return nil, false
	}
	if defaultScheme == "" {
		defaultScheme = "https"
	}

	candidate := raw
	if !strings.Contains(candidate, "://") {
		hostPart := candidate
		if idx := strings.Index(hostPart, "/"); idx >= 0 {
			hostPart = hostPart[:idx]
		}
		if hostPart == "" {
			return nil, false
		}
		if strings.Contains(hostPart, ".") || net.ParseIP(hostPart) != nil {
			candidate = defaultScheme + "://" + candidate
		} else {
			return nil, false
		}
	}

	u, err := url.Parse(candidate)
	if err != nil || u.Host == "" {
		return nil, false
	}

	host := u.Hostname()
	if host == "" {
		return nil, false
	}

	parts := &importURLParts{
		scheme:      u.Scheme,
		path:        u.Path,
		urlOverride: candidate,
	}
	if parts.path == "" {
		parts.path = "/"
	}

	if ip := net.ParseIP(host); ip != nil {
		parts.targetType = model.MonitorTargetTypeIP
		parts.targetValue = host
		if u.Port() != "" {
			parts.virtualHost = net.JoinHostPort(host, u.Port())
		} else {
			parts.virtualHost = host
		}
	} else {
		parts.targetType = model.MonitorTargetTypeDomain
		parts.targetValue = host
	}

	return parts, true
}

func cell(row []string, idx int) string {
	if idx < len(row) {
		return strings.TrimSpace(row[idx])
	}
	return ""
}

func isTemplateHelperRow(row []string) bool {
	first := strings.TrimSpace(safeGet(row, 0))
	second := strings.TrimSpace(safeGet(row, 1))
	if first == "可选，留空自动取域名" || first == "示例官网" {
		return true
	}
	if second == "domain 或 ip，留空自动识别" {
		return true
	}
	if first == "HTTPS 示例" || first == "HTTP 示例" {
		return true
	}
	return false
}

func safeGet(row []string, idx int) string {
	if idx < len(row) {
		return row[idx]
	}
	return ""
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func (s *serviceMonitor) buildExistingTargetIndex(db *gorm.DB) map[string]*model.MonitorTarget {
	var targets []model.MonitorTarget
	db.Select("id, target_value, asset_id").Find(&targets)
	idx := make(map[string]*model.MonitorTarget, len(targets))
	for i := range targets {
		idx[strings.ToLower(targets[i].TargetValue)] = &targets[i]
	}
	return idx
}

func (s *serviceMonitor) buildExistingTaskIndex(db *gorm.DB) map[string]bool {
	type taskRow struct {
		TargetValue string
		URLOverride string
		Path        string
	}
	var rows []taskRow
	db.Model(&model.MonitorPathTask{}).
		Select("t.target_value, pt.url_override, pt.path").
		Joins("AS pt INNER JOIN monitor_targets t ON t.id = pt.target_id").
		Scan(&rows)
	idx := make(map[string]bool, len(rows))
	for _, r := range rows {
		url := r.URLOverride
		if url == "" {
			url = r.Path
		}
		key := strings.ToLower(r.TargetValue + "|" + url)
		idx[key] = true
	}
	return idx
}

func (s *serviceMonitor) buildAssetIndex(db *gorm.DB) map[string]string {
	type assetRow struct {
		ID      string
		Domain  string
		IPv4    string
		Address string
	}
	var rows []assetRow
	db.Model(&model.Asset{}).Select("id, domain, ipv4, address").Find(&rows)

	idx := make(map[string]string, len(rows)*2)
	conflicts := make(map[string]bool)

	addKey := func(key, id string) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || len(key) < 4 {
			return
		}
		if existing, ok := idx[key]; ok {
			if existing != id {
				conflicts[key] = true
			}
			return
		}
		idx[key] = id
	}

	for _, r := range rows {
		if r.Domain != "" {
			addKey(r.Domain, r.ID)
		}
		if r.IPv4 != "" {
			addKey(r.IPv4, r.ID)
		}
		if r.Address != "" {
			addr := strings.TrimSpace(r.Address)
			if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
				addKey(u.Hostname(), r.ID)
			}
		}
	}

	for key := range conflicts {
		delete(idx, key)
	}
	return idx
}

func mergeWithSeeds(defaults map[string]map[string]any) map[string]map[string]any {
	if defaults == nil {
		defaults = make(map[string]map[string]any)
	}
	allDims := append(model.MonitorPathDimensions, model.MonitorTargetDimensions...)
	for _, dim := range allDims {
		seeds, hasSeed := model.MonitorDefaultConfigSeeds[dim]
		if !hasSeed {
			continue
		}
		existing, hasExisting := defaults[dim]
		if !hasExisting {
			merged := make(map[string]any)
			for k, v := range seeds {
				merged[k] = v
			}
			defaults[dim] = merged
			continue
		}
		for k, v := range seeds {
			if _, exists := existing[k]; !exists {
				existing[k] = v
			}
		}
	}
	return defaults
}

func (s *serviceMonitor) loadDefaultConfigs(ctx context.Context) (map[string]map[string]any, error) {
	var configs []model.MonitorDefaultConfig
	if err := s.session().WithContext(ctx).Find(&configs).Error; err != nil {
		return nil, err
	}
	result := make(map[string]map[string]any)
	for _, c := range configs {
		result[c.Dimension] = c.ConfigJSON
	}
	return result, nil
}

func (s *serviceMonitor) GetImportResult(_ context.Context, importID string) (*contract.ImportResult, error) {
	s.importMu.RLock()
	defer s.importMu.RUnlock()
	r, ok := s.importResults[importID]
	if !ok {
		return nil, fmt.Errorf("导入任务不存在: %s", importID)
	}
	snapshot := *r
	snapshot.Results = make([]contract.ImportRowResult, len(r.Results))
	copy(snapshot.Results, r.Results)
	return &snapshot, nil
}

func (s *serviceMonitor) ExportImportResult(_ context.Context, importID string) ([]byte, error) {
	s.importMu.RLock()
	r, ok := s.importResults[importID]
	if !ok {
		s.importMu.RUnlock()
		return nil, fmt.Errorf("导入任务不存在: %s", importID)
	}
	snapshot := *r
	snapshot.Results = make([]contract.ImportRowResult, len(r.Results))
	copy(snapshot.Results, r.Results)
	s.importMu.RUnlock()

	ef := excelize.NewFile()
	defer ef.Close()
	sheet := "导入结果"
	ef.SetSheetName("Sheet1", sheet)

	headers := []string{"行号", "名称", "URL", "结果", "任务ID", "错误信息"}
	for i, h := range headers {
		c, _ := excelize.CoordinatesToCellName(i+1, 1)
		ef.SetCellValue(sheet, c, h)
	}
	for i, rr := range snapshot.Results {
		row := i + 2
		ef.SetCellValue(sheet, cellName(1, row), rr.Row)
		ef.SetCellValue(sheet, cellName(2, row), rr.Name)
		ef.SetCellValue(sheet, cellName(3, row), rr.URL)
		if rr.Success {
			ef.SetCellValue(sheet, cellName(4, row), "成功")
		} else {
			ef.SetCellValue(sheet, cellName(4, row), "失败")
		}
		ef.SetCellValue(sheet, cellName(5, row), rr.TaskID)
		ef.SetCellValue(sheet, cellName(6, row), rr.Error)
	}
	var buf bytes.Buffer
	if err := ef.Write(&buf); err != nil {
		return nil, fmt.Errorf("生成导出文件失败: %w", err)
	}
	return buf.Bytes(), nil
}

func cellName(col, row int) string {
	name, _ := excelize.CoordinatesToCellName(col, row)
	return name
}
