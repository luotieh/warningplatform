package input

import (
	"context"
	"fmt"
	"mime/multipart"
	"strings"
	"time"
	"vulnscan-backend/circular/paging"
	circularScope "vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	inputContract "vulnscan-backend/circular/input/input-contract"
	"vulnscan-backend/formdesign"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"gorm.io/gorm"
)

type serviceInput struct {
	db *db.DB
}

func NewServiceInput(database *db.DB) *serviceInput {
	return &serviceInput{db: database}
}

func (s *serviceInput) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceInput) Add(ctx context.Context, req inputContract.InputAddReq, actor circularScope.Actor) (string, error) {
	if req.Title == "" {
		return "", fmt.Errorf("通报标题不能为空")
	}

	sess := s.session()
	now := time.Now()
	id := qulid.GenerateID()
	circular := model.Circular{
		Code:               id,
		Title:              req.Title,
		Source:             model.CircularSourceManualInput,
		Organize:           req.Organize,
		CircularData:       req.CircularData,
		ProcessingDeadline: req.ProcessingDeadline,
		Status:             model.CircularToBeSubmit,
		CircularTemplate:   req.CircularTemplate,
	}
	circular.Id = id
	circular.CreatedBy = actor.ID
	circular.CreatedAt = now
	circular.UpdatedAt = now

	err := sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		if err := session.Create(&circular).Error; err != nil {
			return err
		}
		opLog := model.BuildCircularOperationLog(id, model.CircularOpInput, actor.ID, actor.Name, "录入成功", "", map[string]interface{}{
			"title":  req.Title,
			"source": string(model.CircularSourceManualInput),
		})
		return session.Create(&opLog).Error
	})
	if err != nil {
		return "", err
	}
	return circular.Id, nil
}

func (s *serviceInput) List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error) {
	var items []inputContract.ListResp
	org := circularScope.GetOrganize(c)

	sess := s.session()
	tx := sess.WithContext(c).Model(&model.Circular{}).Where("status != ? AND organize = ?", model.CircularCompleted, org)

	if req.Status != "" {
		tx = tx.Where("status = ?", req.Status)
	}
	if req.Title != "" {
		tx = tx.Where("title LIKE ?", "%"+req.Title+"%")
	}
	if req.Code != "" {
		tx = tx.Where("code = ?", req.Code)
	}

	var count int64
	if err := tx.Count(&count).Error; err != nil {
		return 0, nil, err
	}

	page, size := paging.Normalize(req.Page, req.Size)
	offset := (page - 1) * size
	if err := tx.Offset(offset).Limit(size).Order("created_at DESC").Find(&items).Error; err != nil {
		return 0, nil, err
	}

	return count, items, nil
}

func (s *serviceInput) Detail(ctx context.Context, id string) (*inputContract.InputDetailResp, error) {
	if id == "" {
		return nil, fmt.Errorf("id不能为空")
	}

	sess := s.session()
	var circular model.Circular
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&circular).Error; err != nil {
		return nil, fmt.Errorf("通报不存在")
	}

	result := &inputContract.InputDetailResp{Circular: circular}

	if err := sess.WithContext(ctx).Where("circular_id = ?", circular.Code).Find(&result.OrganizeStatusList).Error; err != nil {
		return nil, err
	}
	if err := sess.WithContext(ctx).Where("circular_id = ?", circular.Code).Find(&result.Distributions).Error; err != nil {
		return nil, err
	}
	if err := sess.WithContext(ctx).Where("circular = ?", circular.Id).Find(&result.Disposals).Error; err != nil {
		return nil, err
	}
	if err := sess.WithContext(ctx).Where("circular_id = ?", circular.Code).Find(&result.Reviews).Error; err != nil {
		return nil, err
	}

	return result, nil
}

func (s *serviceInput) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("id不可为空")
	}
	sess := s.session()

	var circular model.Circular
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	return sess.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		code := circular.Code

		tx.Where("circular_id = ?", code).Delete(&model.CircularOrganizeStatus{})
		tx.Where("circular_id = ?", code).Delete(&model.CircularReview{})
		tx.Where("circular_id = ?", code).Delete(&model.CircularOperationLog{})

		var distIds []string
		tx.Model(&model.CircularDistribution{}).Where("circular_id = ?", code).Pluck("id", &distIds)
		if len(distIds) > 0 {
			tx.Where("ancestor IN ? OR descendant IN ?", distIds, distIds).Delete(&model.CircularDistributionClosure{})
		}
		tx.Where("circular_id = ?", code).Delete(&model.CircularDistribution{})

		tx.Where("circular = ?", id).Delete(&model.CircularDisposal{})

		return tx.Where("id = ?", id).Delete(&model.Circular{}).Error
	})
}

func (s *serviceInput) Edit(ctx context.Context, id string, req inputContract.InputEditReq, actor circularScope.Actor) error {
	if id == "" {
		return fmt.Errorf("id不能为空")
	}

	sess := s.session()
	var circular model.Circular
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	updates := make(map[string]any)
	if req.Title != nil {
		updates["title"] = *req.Title
	}
	if req.Organize != nil {
		updates["organize"] = *req.Organize
	}
	if req.ProcessingDeadline != nil {
		updates["processing_deadline"] = *req.ProcessingDeadline
	}
	if req.CircularData != nil {
		v, _ := req.CircularData.Value()
		updates["circular_data"] = v
	}

	if len(updates) > 0 {
		updates["updated_by"] = actor.ID
		return sess.WithContext(ctx).Model(&model.Circular{}).Where("id = ?", id).Updates(updates).Error
	}
	return nil
}

func (s *serviceInput) Submit(ctx context.Context, id string, actor circularScope.Actor) error {
	if id == "" {
		return fmt.Errorf("id不能为空")
	}

	sess := s.session()
	var circular model.Circular
	if err := sess.WithContext(ctx).Where("id = ?", id).First(&circular).Error; err != nil {
		return fmt.Errorf("通报不存在")
	}

	if _, err := model.CircularSM.Apply(circular.Status, model.CircularEvtSubmit); err != nil {
		return err
	}

	return sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		if err := session.Model(&model.Circular{}).Where("id = ?", id).Updates(map[string]interface{}{
			"status":     model.CircularToBeVerified,
			"updated_by": actor.ID,
		}).Error; err != nil {
			return err
		}

		opLog := model.BuildCircularOperationLog(circular.Code, model.CircularOpSubmit, actor.ID, actor.Name, "提交核验", "", map[string]interface{}{
			"title": circular.Title,
		})
		return session.Create(&opLog).Error
	})
}

func (s *serviceInput) ThirdPartyImport(ctx context.Context, req inputContract.InputAddReq, actor circularScope.Actor, ownerOrganize string) error {
	if req.Title == "" {
		return fmt.Errorf("通报标题不能为空")
	}

	sess := s.session()
	now := time.Now()
	id := qulid.GenerateID()
	circular := model.Circular{
		Code:             id,
		Title:            req.Title,
		Source:           model.CircularSourceThirdPartyImport,
		Organize:         circularScope.ResolveOrganize(req.Organize, ownerOrganize),
		CircularData:     req.CircularData,
		Status:           model.CircularToBeVerified,
		CircularTemplate: req.CircularTemplate,
	}
	circular.Id = id
	circular.CreatedBy = actor.ID
	circular.CreatedAt = now
	circular.UpdatedAt = now

	return sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		if err := session.Create(&circular).Error; err != nil {
			return err
		}
		opLog := model.BuildCircularOperationLog(id, model.CircularOpThirdPartyImport, actor.ID, actor.Name, "第三方导入成功", "", map[string]interface{}{
			"title":  req.Title,
			"source": string(model.CircularSourceThirdPartyImport),
		})
		return session.Create(&opLog).Error
	})
}

func (s *serviceInput) Export(ctx context.Context, codes []string) error {
	if len(codes) == 0 {
		return fmt.Errorf("codes不能为空")
	}

	sess := s.session()
	var notices []model.CircularInputNotice
	if err := sess.WithContext(ctx).Preload("InvolvedAssets").Preload("HazardInfo").
		Where("code IN ?", codes).Find(&notices).Error; err != nil {
		return err
	}

	f := excelize.NewFile()
	sheet := "录入通报"
	index, _ := f.NewSheet(sheet)
	f.SetActiveSheet(index)

	headers := []string{
		"序号", "隐患编号", "数据编号", "隐患名称",
		"厂商上报归属地(省)", "厂商上报归属地(市)", "厂商上报归属地区(区/县)",
		"隐患URL", "系族名称", "网站域名IP", "网站IP",
		"归属地(省)", "归属地(市)", "归属地区(区/县)",
		"隐患类型", "预警级别", "隐患级别", "发现时间",
		"上报厂商", "厂商上报时间", "涉及信息数量", "涉及信息类型",
		"隶属单位", "单位类型", "所属行业", "工信部备案号",
		"等级级别", "备案备案号", "隐患描述",
	}
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = f.SetCellValue(sheet, cell, header)
	}

	for rowIdx, notice := range notices {
		region := splitRegion(notice.InvolvedAssets.PlaceOrigin)
		manRegion := splitRegion(notice.HazardInfo.ManufacturerLocation)

		values := []interface{}{
			rowIdx + 1, notice.HazardInfo.HazardNumber, notice.HazardInfo.DataNumber, notice.HazardInfo.HazardName,
			manRegion[0], manRegion[1], manRegion[2],
			notice.HazardInfo.HazardURL, notice.InvolvedAssets.SystemName,
			notice.InvolvedAssets.WebsiteDomain, notice.InvolvedAssets.WebsiteIP,
			region[0], region[1], region[2],
			notice.HazardInfo.HazardType,
			model.CircularWarningLevelMap[notice.HazardInfo.WarningLevel],
			model.CircularDangerLevelMap[notice.HazardInfo.HazardLevel],
			notice.HazardInfo.DiscoveryTime, notice.HazardInfo.ReportingVendor,
			notice.HazardInfo.VendorReportTime, notice.HazardInfo.InvolveInfoAmount,
			notice.HazardInfo.InvolveInfoType, notice.InvolvedAssets.AffiliatedUnit,
			notice.InvolvedAssets.UnitType, notice.InvolvedAssets.Industry,
			notice.InvolvedAssets.RegisterNumber,
			model.CircularSecurityLevelMap[notice.InvolvedAssets.SecurityLevel],
			notice.InvolvedAssets.SecurityRegisterNumber,
			notice.HazardInfo.HazardDescription,
		}
		for colIdx, value := range values {
			cell, _ := excelize.CoordinatesToCellName(colIdx+1, rowIdx+2)
			_ = f.SetCellValue(sheet, cell, value)
		}
	}

	_ = f.DeleteSheet("Sheet1")
	tempFile := "./input_notices-" + time.Now().Format("2006-01-02_15-04-05") + ".xlsx"
	return f.SaveAs(tempFile)
}

func (s *serviceInput) Import(ctx context.Context, file *multipart.FileHeader, actor circularScope.Actor) (int, error) {
	open, err := file.Open()
	if err != nil {
		return 0, err
	}
	defer open.Close()

	f, err := excelize.OpenReader(open)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	list := f.GetSheetList()
	if len(list) == 0 {
		return 0, fmt.Errorf("excel表单为空")
	}

	rows, err := f.GetRows(list[0])
	if err != nil {
		return 0, err
	}

	const dataStartRow = 7
	if len(rows) <= dataStartRow {
		return 0, fmt.Errorf("excel数据为空")
	}

	defaultTemplateId := s.getDefaultTemplateId(ctx)
	sess := s.session()

	var count int
	for i, row := range rows[dataStartRow:] {
		if len(row) < 29 {
			continue
		}

		noticeMap := buildImportNoticeMap(row)
		noticeCode := qulid.GenerateID()
		now := time.Now()
		item := model.Circular{
			Code:             noticeCode,
			Title:            "默认模板文件导入",
			Source:           model.CircularSourceTemplateImport,
			CircularTemplate: defaultTemplateId,
			CircularData:     noticeMap,
			Status:           model.CircularToBeSubmit,
		}
		item.Id = noticeCode
		item.CreatedBy = actor.ID
		item.CreatedAt = now
		item.UpdatedAt = now

		err := sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
			if err := session.Create(&item).Error; err != nil {
				return err
			}
			opLog := model.BuildCircularOperationLog(noticeCode, model.CircularOpImport, actor.ID, actor.Name, "导入成功", "", map[string]interface{}{
				"title":  "默认模板文件导入",
				"source": string(model.CircularSourceTemplateImport),
			})
			return session.Create(&opLog).Error
		})
		if err != nil {
			return count, fmt.Errorf("第%d行数据导入失败: %s", i+2, err.Error())
		}
		count++
	}

	return count, nil
}

func (s *serviceInput) CommonTemplateDownload(c *gin.Context) {
	f := excelize.NewFile()
	sheetName := "录入通报-通用模板"
	index, _ := f.NewSheet(sheetName)
	f.SetActiveSheet(index)

	for row := 1; row <= 6; row++ {
		startCell, _ := excelize.CoordinatesToCellName(1, row)
		endCell, _ := excelize.CoordinatesToCellName(29, row)
		f.MergeCell(sheetName, startCell, endCell)
	}

	f.SetCellValue(sheetName, "A1", "说明：")
	f.SetCellValue(sheetName, "A2", "    1. 使用模板时，请注意保护模板格式的完整性")
	f.SetCellValue(sheetName, "A3", "    2. 日期格式必须为: yyyy-MM-dd hh:mm:ss")
	f.SetCellValue(sheetName, "A4", "    3. 省市县格式必须为全称")
	f.SetCellValue(sheetName, "A5", "    4. 单位名称必须填写全称")
	f.SetCellRichText(sheetName, "A6", []excelize.RichTextRun{
		{Text: "    5. 标红字段为必填项", Font: &excelize.Font{Color: "FF0000", Bold: true}},
	})

	headers := []struct {
		name string
		red  bool
	}{
		{"序号", false}, {"隐患编号", true}, {"数据编号", false}, {"隐患名称", true},
		{"厂商上报归属地(省)", false}, {"厂商上报归属地(市)", false}, {"厂商上报归属地区(区/县)", false},
		{"隐患URL", true}, {"系族名称", true}, {"网站域名IP", true}, {"网站 IP", true},
		{"归属地(省)", true}, {"归属地(市)", true}, {"归属地区(区/县)", true},
		{"隐患类型", true}, {"预警级别", true}, {"隐患级别", true}, {"发现时间", true},
		{"上报厂商", false}, {"厂商上报时间", true}, {"涉及信息数量", false}, {"涉及信息类型", false},
		{"隶属单位", true}, {"单位类型", true}, {"所属行业", true}, {"工信部备案号", false},
		{"等级级别", true}, {"备案备案号", true}, {"隐患描述", true},
	}

	normalStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
	})
	redStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FF0000"},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
	})

	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 7)
		_ = f.SetCellValue(sheetName, cell, h.name)
		if h.red {
			f.SetCellStyle(sheetName, cell, cell, redStyle)
		} else {
			f.SetCellStyle(sheetName, cell, cell, normalStyle)
		}
	}

	f.SetRowHeight(sheetName, 7, 40)
	_ = f.DeleteSheet("Sheet1")

	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", `attachment; filename="常规导入模板.xlsx"`)
	f.Write(c.Writer)
}

func (s *serviceInput) getDefaultTemplateId(ctx context.Context) string {
	item, err := formdesign.ResolveCircularInputTemplate(s.session(), ctx)
	if err != nil {
		return ""
	}
	return item.ID
}

func splitRegion(address string) [3]string {
	var result [3]string
	parts := strings.Split(address, "/")
	for i := 0; i < 3 && i < len(parts); i++ {
		result[i] = parts[i]
	}
	return result
}

func getValue(row []string, index int) string {
	if index < len(row) {
		return row[index]
	}
	return ""
}

func buildImportNoticeMap(row []string) model.JSONMapSlice {
	fields := []struct {
		title string
		idx   int
	}{
		{"隐患编号", 1}, {"数据编号", 2}, {"隐患名称", 3},
		{"厂商上报归属地", -1}, {"隐患URL", 7}, {"系统名称", 8},
		{"网站域名IP", 9}, {"网站IP", 10}, {"归属地", -2},
		{"隐患类型", 14}, {"预警级别", 15}, {"隐患级别", 16},
		{"发现时间", 17}, {"上报厂商", 18}, {"厂商上报时间", 19},
		{"涉及信息数量", 20}, {"涉及信息类型", 21}, {"隶属单位", 22},
		{"单位类型", 23}, {"所属行业", 24}, {"工信部备案号", 25},
		{"等保级别", 26}, {"等保备案号", 27}, {"隐患描述", 28},
	}

	noticeMap := make(model.JSONMapSlice, 0, len(fields))
	for _, f := range fields {
		var value string
		switch f.idx {
		case -1:
			value = getValue(row, 4) + "/" + getValue(row, 5) + "/" + getValue(row, 6)
		case -2:
			value = getValue(row, 11) + "/" + getValue(row, 12) + "/" + getValue(row, 13)
		default:
			value = getValue(row, f.idx)
		}
		noticeMap = append(noticeMap, map[string]any{
			"title": f.title, "type": "input", "value": value,
		})
	}
	return noticeMap
}
