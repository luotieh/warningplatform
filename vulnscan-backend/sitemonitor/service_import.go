package sitemonitor

import (
	"bytes"
	"context"
	"fmt"
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
		"名称", "目标类型", "目标值", "请求Host", "监测URL",
		"可用性", "域名劫持", "篡改", "敏感词", "敏感文件", "暗链",
	}
	descriptions := []string{
		"可选，留空自动取域名",
		"domain 或 ip，留空自动识别",
		"域名或IP，填URL时可留空",
		"仅IP目标必填，如 www.example.com",
		"完整URL或路径，留空默认 /",
		"留空=启用，填\"关闭\"=不启用",
		"同左",
		"同左",
		"同左",
		"同左",
		"同左",
	}
	examples := []string{
		"示例官网",
		"",
		"",
		"",
		"https://www.example.com",
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

	colWidths := []float64{16, 14, 22, 24, 32, 10, 10, 10, 10, 10, 10}
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

	f.SetRowHeight(sheet, 1, 28)
	f.SetRowHeight(sheet, 2, 36)
	f.SetRowHeight(sheet, 3, 22)

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

		if targetType == "" && strings.Contains(pathOrURL, "://") {
			u, err := url.Parse(pathOrURL)
			if err != nil || u.Host == "" {
				rowResult.Error = "无法解析 URL"
				result.Failed++
				result.Results = append(result.Results, rowResult)
				continue
			}
			targetType = model.MonitorTargetTypeDomain
			targetValue = u.Hostname()
			if u.Path != "" {
				pathOrURL = u.Path
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
			Name:        name,
			TargetType:  targetType,
			TargetValue: targetValue,
			VirtualHost: virtualHost,
			Enabled:     true,
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
			idx int
			dim string
		}{
			{5, "availability"}, {6, "domain_hijack"}, {7, "tamper"},
			{8, "sensitive_word"}, {9, "sensitive_file"}, {10, "blacklink"},
		} {
			enabled := cell(row, dc.idx) != "关闭"
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
