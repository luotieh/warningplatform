package sitemonitor

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"code.yt-security.com/public/core/v2/generate/qulid"
	"github.com/xuri/excelize/v2"
)

// ══ 导入 ══

func (s *serviceMonitor) GenerateImportTemplate(_ context.Context) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	sheet := "监测任务导入"
	f.SetSheetName("Sheet1", sheet)

	headers := []string{
		"系统名称", "首页URL（必填）", "目标域名", "目标IP（多个用逗号分隔）",
		"可用性监测", "域名劫持监测", "篡改监测", "敏感词检测", "敏感文件检测", "黑链检测",
	}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, h)
	}

	dvRange := excelize.NewDataValidation(true)
	dvRange.Sqref = "E2:J1000"
	dvRange.SetDropList([]string{"开启", "关闭"})
	f.AddDataValidation(sheet, dvRange)

	colWidths := map[string]float64{
		"A": 20, "B": 40, "C": 25, "D": 30,
		"E": 12, "F": 12, "G": 12, "H": 12, "I": 12, "J": 12,
	}
	for col, width := range colWidths {
		f.SetColWidth(sheet, col, col, width)
	}

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
		ID:        qulid.GenerateID(),
		Total:     len(rows) - 1,
		CreatedAt: time.Now().Format(time.RFC3339),
	}

	defaults, _ := s.loadDefaultConfigs(ctx)

	for i, row := range rows {
		if i == 0 {
			continue
		}
		rowResult := contract.ImportRowResult{Row: i + 1}
		if len(row) < 2 || strings.TrimSpace(row[1]) == "" {
			rowResult.Error = "首页URL为空"
			result.Failed++
			result.Results = append(result.Results, rowResult)
			continue
		}

		targetURL := strings.TrimSpace(row[1])
		rowResult.URL = targetURL

		task := model.MonitorTask{
			TargetHomepage: targetURL,
		}
		task.ID = qulid.GenerateID()
		if len(row) > 0 {
			task.TaskName = strings.TrimSpace(row[0])
		}
		if task.TaskName == "" {
			task.TaskName = targetURL
		}
		rowResult.Name = task.TaskName
		if len(row) > 2 {
			task.TargetDomain = strings.TrimSpace(row[2])
		}
		if len(row) > 3 {
			task.TargetIps = strings.TrimSpace(row[3])
		}
		task.Enabled = true

		dimCols := []struct {
			idx int
			dim string
		}{
			{4, "availability"}, {5, "domain_hijack"}, {6, "tamper"},
			{7, "sensitive_word"}, {8, "sensitive_file"}, {9, "blacklink"},
		}
		for _, dc := range dimCols {
			enabled := true
			if len(row) > dc.idx {
				enabled = strings.TrimSpace(row[dc.idx]) != "关闭"
			}
			cfg := map[string]any{"enabled": enabled}
			if defCfg, ok := defaults[dc.dim]; ok {
				for k, v := range defCfg {
					if k != "enabled" {
						cfg[k] = v
					}
				}
			}
			task.SetDimensionConfig(dc.dim, cfg)
		}

		if err := s.session().WithContext(ctx).Create(&task).Error; err != nil {
			rowResult.Error = err.Error()
			result.Failed++
		} else {
			rowResult.Success = true
			rowResult.TaskID = task.ID
			result.Success++
		}
		result.Results = append(result.Results, rowResult)
	}

	return result, nil
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
	return nil, fmt.Errorf("导入结果缓存未实现（需Redis）")
}

func (s *serviceMonitor) ExportImportResult(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("导出导入结果未实现（需Redis）")
}
