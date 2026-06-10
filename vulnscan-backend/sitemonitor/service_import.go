package sitemonitor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/generate/ulid"
	"github.com/xuri/excelize/v2"
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

	result := &contract.ImportResult{
		ID:        ulid.GenerateID(),
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	defaults, _ := s.loadDefaultConfigs(ctx)
	useSchemeColumn := importUsesSchemeColumn(rows)

	for i, row := range rows {
		if i == 0 {
			continue
		}
		if isTemplateHelperRow(row) {
			continue
		}
		rowResult := contract.ImportRowResult{Row: i + 1}
		name := cell(row, 0)
		targetType := strings.ToLower(cell(row, 1))
		targetValue := cell(row, 2)
		virtualHost := cell(row, 3)
		pathOrURL := cell(row, 4)
		if pathOrURL == "" {
			pathOrURL = "/"
		}

		defaultScheme := "https"
		dimStart := 5
		schemeSpecified := false
		if useSchemeColumn {
			if scheme := normalizeImportScheme(cell(row, 5)); scheme != "" {
				defaultScheme = scheme
				schemeSpecified = true
			}
			dimStart = 6
		}

		if !schemeSpecified && !strings.Contains(pathOrURL, "://") && pathOrURL != "" && pathOrURL != "/" {
			if detected := detectImportScheme(ctx, pathOrURL); detected != "" {
				defaultScheme = detected
			}
		}

		if parsed, ok := parseImportMonitorURL(pathOrURL, defaultScheme); ok {
			if targetType == "" {
				targetType = parsed.targetType
			}
			if targetValue == "" {
				targetValue = parsed.targetValue
			}
			if virtualHost == "" {
				virtualHost = parsed.virtualHost
			}
			if parsed.scheme != "" {
				defaultScheme = parsed.scheme
			}
			if parsed.urlOverride != "" {
				pathOrURL = parsed.urlOverride
			} else if parsed.path != "" {
				pathOrURL = parsed.path
			}
		}
		if targetValue == "" {
			rowResult.Error = "目标值为空"
			result.Failed++
			result.Results = append(result.Results, rowResult)
			continue
		}
		if name == "" {
			name = targetValue
		}
		rowResult.Name = name
		rowResult.URL = pathOrURL

		target := &model.MonitorTarget{
			Name:          name,
			TargetType:    targetType,
			TargetValue:   targetValue,
			DefaultScheme: defaultScheme,
			VirtualHost:   virtualHost,
			Enabled:       true,
		}
		target.ID = ulid.GenerateID()
		if err := s.CreateTarget(ctx, target); err != nil {
			rowResult.Error = err.Error()
			result.Failed++
			result.Results = append(result.Results, rowResult)
			continue
		}

		pt := &model.MonitorPathTask{
			TargetID: target.ID,
			Name:     name,
			Enabled:  true,
		}
		if strings.Contains(pathOrURL, "://") {
			pt.URLOverride = pathOrURL
		} else {
			pt.Path = pathOrURL
		}
		for _, dc := range []struct {
			offset int
			dim    string
		}{
			{0, "availability"}, {1, "domain_hijack"}, {2, "tamper"},
			{3, "sensitive_word"}, {4, "sensitive_file"}, {5, "blacklink"},
		} {
			enabled := cell(row, dimStart+dc.offset) != "关闭"
			cfg := map[string]any{"enabled": enabled}
			if defCfg, ok := defaults[dc.dim]; ok {
				for k, v := range defCfg {
					if k != "enabled" {
						cfg[k] = v
					}
				}
			}
			if contains(model.MonitorPathDimensions, dc.dim) {
				pt.SetDimensionConfig(dc.dim, cfg)
			} else if contains(model.MonitorTargetDimensions, dc.dim) {
				target.SetDimensionConfig(dc.dim, cfg)
			}
		}
		if err := s.session().WithContext(ctx).Model(target).Updates(map[string]any{
			"config_domain_hijack":  target.ConfigDomainHijack,
			"config_sensitive_file": target.ConfigSensitiveFile,
		}).Error; err != nil {
			rowResult.Error = err.Error()
			result.Failed++
			result.Results = append(result.Results, rowResult)
			continue
		}
		if err := s.CreatePathTask(ctx, pt); err != nil {
			rowResult.Error = err.Error()
			result.Failed++
		} else {
			rowResult.Success = true
			rowResult.TaskID = pt.ID
			result.Success++
		}
		result.Results = append(result.Results, rowResult)
	}
	result.Total = result.Success + result.Failed
	return result, nil
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
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
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

func (s *serviceMonitor) GetImportResult(_ context.Context, _ string) (*contract.ImportResult, error) {
	return nil, fmt.Errorf("导入结果缓存未实现")
}

func (s *serviceMonitor) ExportImportResult(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("导出导入结果未实现")
}
