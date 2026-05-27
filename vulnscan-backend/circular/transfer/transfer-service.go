package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	transferContract "vulnscan-backend/circular/transfer/transfer-contract"
	"vulnscan-backend/formdesign"

	"code.yt-security.com/public/core/v2/db"
	"code.yt-security.com/public/core/v2/generate/qulid"
	"gorm.io/gorm"
)

type serviceTransfer struct {
	db       *db.DB
	reporter transferContract.IncidentReportExporter
}

func NewServiceTransfer(database *db.DB) *serviceTransfer {
	return &serviceTransfer{db: database}
}

func (s *serviceTransfer) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceTransfer) ReceiveIncident(ctx context.Context, req transferContract.TransferIncidentReq, actor scope.Actor, ownerOrganize string) (string, error) {
	if req.IncidentNo == "" {
		return "", fmt.Errorf("隐患编号不能为空")
	}

	sess := s.session()

	var existing model.Circular
	if err := sess.WithContext(ctx).Where("custom_code = ?", req.IncidentNo).First(&existing).Error; err == nil {
		return existing.Code, nil
	}

	defaultTemplate, err := formdesign.ResolveCircularInputTemplate(sess, ctx)
	if err != nil {
		return "", err
	}

	now := time.Now()
	circularCode := qulid.GenerateID()
	circularData := buildCircularDataFromIncident(req)
	circularData = s.attachIncidentReports(ctx, circularCode, req, circularData)

	unitOrganize := ""
	if req.AssetInfo != nil {
		unitOrganize = req.AssetInfo.Unit
	}
	circular := model.Circular{
		Code: circularCode, Title: req.Name, CustomCode: req.IncidentNo,
		Source:           model.CircularSourceSuperiorTransfer,
		Organize:         scope.ResolveOrganize(unitOrganize, ownerOrganize),
		CircularTemplate: defaultTemplate.ID, CircularData: circularData, Status: model.CircularToBeDistributed,
	}
	circular.Id = circularCode
	circular.CreatedBy = actor.ID
	circular.CreatedAt = now
	circular.UpdatedAt = now

	err = sess.WithContext(ctx).Transaction(func(session *gorm.DB) error {
		if err := session.Create(&circular).Error; err != nil {
			return err
		}

		transferRecord := model.CircularTransferRecord{
			CircularId: circularCode, IncidentID: req.IncidentID, IncidentNo: req.IncidentNo,
			SourceSystem: req.SourceSystem, TransferTime: now.Format("2006-01-02 15:04:05"),
			SourceData: toJSONString(req),
		}
		transferRecord.Id = qulid.GenerateID()
		transferRecord.CreatedAt = now
		transferRecord.UpdatedAt = now
		if err := session.Create(&transferRecord).Error; err != nil {
			return err
		}

		opLog := model.BuildCircularOperationLog(circularCode, model.CircularOpThirdPartyImport, actor.ID, actor.Name, "安全事件流转成功", "", map[string]interface{}{
			"incident_no": req.IncidentNo, "incident_id": req.IncidentID, "incident_name": req.Name, "source_system": req.SourceSystem,
		})
		if err := session.Create(&opLog).Error; err != nil {
			return err
		}

		verifyLog := model.BuildCircularOperationLog(circularCode, model.CircularOpVerifyPass, actor.ID, actor.Name, "自动核验（安全事件已复核）", "", map[string]interface{}{
			"auto":          true,
			"reason":        "源安全事件已通过人工复核，跳过通报核验环节",
			"source_system": req.SourceSystem,
		})
		return session.Create(&verifyLog).Error
	})

	if err != nil {
		return "", err
	}
	return circularCode, nil
}

func (s *serviceTransfer) ReceiveIncidentBatch(ctx context.Context, req transferContract.TransferIncidentBatchReq, actor scope.Actor, ownerOrganize string) ([]transferContract.TransferResultItem, error) {
	if len(req.Incidents) == 0 {
		return nil, fmt.Errorf("流转数据不能为空")
	}

	results := make([]transferContract.TransferResultItem, 0, len(req.Incidents))
	for _, incident := range req.Incidents {
		circularCode, err := s.ReceiveIncident(ctx, incident, actor, ownerOrganize)
		item := transferContract.TransferResultItem{
			IncidentNo: incident.IncidentNo, Success: err == nil, CircularCode: circularCode,
		}
		if err != nil {
			errMsg := err.Error()
			item.Error = errMsg
		}
		results = append(results, item)
	}
	return results, nil
}

func (s *serviceTransfer) GetTransferStatus(ctx context.Context, incidentNo string) (*transferContract.TransferStatusResp, error) {
	if incidentNo == "" {
		return nil, fmt.Errorf("隐患编号不能为空")
	}

	sess := s.session()
	var record model.CircularTransferRecord
	if err := sess.WithContext(ctx).Where("incident_no = ?", incidentNo).First(&record).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return &transferContract.TransferStatusResp{IncidentNo: incidentNo}, nil
		}
		return nil, err
	}

	var circular model.Circular
	if err := sess.WithContext(ctx).Where("id = ?", record.CircularId).First(&circular).Error; err != nil {
		return nil, err
	}

	return &transferContract.TransferStatusResp{
		IncidentNo: incidentNo, IncidentID: record.IncidentID,
		CircularId: circular.Id, CircularCode: circular.Code,
		Status: string(circular.Status), TransferTime: record.TransferTime,
	}, nil
}

func buildCircularDataFromIncident(req transferContract.TransferIncidentReq) model.JSONMapSlice {
	data := model.JSONMapSlice{
		{"title": "隐患编号", "type": "input", "value": req.IncidentNo},
		{"title": "隐患名称", "type": "input", "value": req.Name},
	}
	if req.Level > 0 {
		levelLabels := map[int]string{1: "特别重大", 2: "重大", 3: "较大", 4: "一般"}
		label := levelLabels[req.Level]
		if label == "" {
			label = fmt.Sprintf("级别%d", req.Level)
		}
		data = append(data, map[string]any{"title": "事件级别", "type": "select", "value": label})
	}
	if req.AssetInfo != nil {
		if req.AssetInfo.AssetName != "" {
			data = append(data, map[string]any{"title": "资产名称", "type": "input", "value": req.AssetInfo.AssetName})
		}
		data = append(data,
			map[string]any{"title": "系统名称", "type": "input", "value": req.AssetInfo.SystemName},
			map[string]any{"title": "网站域名IP", "type": "input", "value": req.AssetInfo.DomainIP},
			map[string]any{"title": "网站IP", "type": "input", "value": req.AssetInfo.SiteIP},
			map[string]any{"title": "归属地", "type": "input", "value": req.AssetInfo.Region},
			map[string]any{"title": "隶属单位", "type": "input", "value": req.AssetInfo.Unit},
			map[string]any{"title": "单位类型", "type": "input", "value": req.AssetInfo.UnitType},
			map[string]any{"title": "所属行业", "type": "input", "value": req.AssetInfo.Industry},
			map[string]any{"title": "等保级别", "type": "select", "value": req.AssetInfo.MLPSLevel},
			map[string]any{"title": "等保备案号", "type": "input", "value": req.AssetInfo.MLPSRecordNo},
		)
	}
	if req.MetadataInfo != nil {
		if req.MetadataInfo.DataNo != "" {
			data = append(data, map[string]any{"title": "数据编号", "type": "input", "value": req.MetadataInfo.DataNo})
		}
		data = append(data,
			map[string]any{"title": "隐患类型", "type": "input", "value": req.MetadataInfo.IncidentType},
			map[string]any{"title": "隐患URL", "type": "input", "value": req.MetadataInfo.IncidentURL},
			map[string]any{"title": "隐患描述", "type": "input", "value": req.MetadataInfo.IncidentDescription},
		)
		if req.MetadataInfo.CveId != "" {
			data = append(data, map[string]any{"title": "CVE编号", "type": "input", "value": req.MetadataInfo.CveId})
		}
		if req.MetadataInfo.CvssScore > 0 {
			data = append(data, map[string]any{"title": "CVSS评分", "type": "input", "value": fmt.Sprintf("%.1f", req.MetadataInfo.CvssScore)})
		}
	}
	if req.AiOpinion != "" {
		data = append(data, map[string]any{"title": "AI预审意见", "type": "input", "value": req.AiOpinion})
	}
	if req.AiConfidence > 0 {
		data = append(data, map[string]any{"title": "AI置信度", "type": "input", "value": fmt.Sprintf("%.0f%%", req.AiConfidence*100)})
	}
	return data
}

func toJSONString(v interface{}) string {
	bs, _ := json.Marshal(v)
	return string(bs)
}
