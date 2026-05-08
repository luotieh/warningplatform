package remediation

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	remediationContract "vulnscan-backend/incident/remediation/remediation-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"github.com/gin-gonic/gin"
)

type HandlerRemediation struct {
	svc remediationContract.ServiceRemediation
}

func NewHandlerRemediation(svc remediationContract.ServiceRemediation) *HandlerRemediation {
	return &HandlerRemediation{svc: svc}
}

func (h *HandlerRemediation) SubmitRemediation(c *gin.Context) {
	req, ok := web.BindJSON[remediationContract.RemediationReq](c)
	if !ok {
		return
	}
	if err := h.svc.SubmitRemediation(c, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerRemediation) VerifyRemediation(c *gin.Context) {
	req, ok := web.BindJSON[remediationContract.VerifyRemediationReq](c)
	if !ok {
		return
	}
	if err := h.svc.VerifyRemediation(c, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerRemediation) CloseIncident(c *gin.Context) {
	req, ok := web.BindJSON[remediationContract.CloseIncidentReq](c)
	if !ok {
		return
	}
	if err := h.svc.CloseIncident(c, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerRemediation) BatchImport(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		web.Fail(c).Msg("请上传CSV文件").Send()
		return
	}
	defer file.Close()

	records, err := ParseCSVImport(file)
	if err != nil {
		web.Fail(c).Msg(fmt.Sprintf("CSV解析失败: %s", err.Error())).Send()
		return
	}

	user, _ := iamsdk.GetCurrentUser(c)
	resp, err := h.svc.BatchImport(c, records, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(resp).Send()
}

func (h *HandlerRemediation) DownloadImportTemplate(c *gin.Context) {
	content := GenerateImportTemplate()
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=incident_import_template.csv")
	// Write UTF-8 BOM for Excel compatibility
	c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})
	c.Writer.Write([]byte(content))
}

// ParseCSVImport reads a CSV file and converts rows to IncidentImportRow slice.
func ParseCSVImport(reader io.Reader) ([]remediationContract.IncidentImportRow, error) {
	r := csv.NewReader(reader)
	r.LazyQuotes = true
	r.TrimLeadingSpace = true

	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("读取表头失败: %w", err)
	}

	// Strip BOM from first header if present
	if len(headers) > 0 {
		headers[0] = strings.TrimPrefix(headers[0], "\xEF\xBB\xBF")
	}

	colIndex := make(map[string]int, len(headers))
	for i, h := range headers {
		colIndex[strings.TrimSpace(h)] = i
	}

	var rows []remediationContract.IncidentImportRow
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取CSV行失败: %w", err)
		}

		row := remediationContract.IncidentImportRow{
			Name:          getCol(record, colIndex, "事件名称"),
			Level:         parseLevelFromText(getCol(record, colIndex, "事件等级")),
			Source:        parseSourceFromText(getCol(record, colIndex, "数据来源")),
			AssetName:     getCol(record, colIndex, "资产名称"),
			SystemName:    getCol(record, colIndex, "系统名称"),
			DomainIP:      getCol(record, colIndex, "域名/IP"),
			Unit:          getCol(record, colIndex, "隶属单位"),
			IncidentType:  getCol(record, colIndex, "事件类型"),
			CvssScore:     parseFloat(getCol(record, colIndex, "CVSS评分")),
			CveId:         getCol(record, colIndex, "CVE编号"),
			OwaspCategory: getCol(record, colIndex, "OWASP分类"),
			ExploitDiff:   getCol(record, colIndex, "利用难度"),
			AffectScope:   getCol(record, colIndex, "影响范围"),
			IncidentURL:   getCol(record, colIndex, "隐患URL"),
			Description:   getCol(record, colIndex, "事件描述"),
			VendorName:    getCol(record, colIndex, "上报厂商"),
			DiscoveryTime: getCol(record, colIndex, "发现时间"),
		}
		rows = append(rows, row)
	}

	return rows, nil
}

// GenerateImportTemplate returns the CSV template content with headers.
func GenerateImportTemplate() string {
	headers := []string{
		"事件名称", "事件等级", "数据来源", "资产名称", "系统名称",
		"域名/IP", "隶属单位", "事件类型", "CVSS评分", "CVE编号",
		"OWASP分类", "利用难度", "影响范围", "隐患URL", "事件描述",
		"上报厂商", "发现时间",
	}
	return strings.Join(headers, ",") + "\n"
}

func getCol(record []string, colIndex map[string]int, name string) string {
	idx, ok := colIndex[name]
	if !ok || idx >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[idx])
}

func parseLevelFromText(text string) int {
	switch text {
	case "紧急":
		return 4
	case "高危":
		return 3
	case "中危":
		return 2
	case "低危":
		return 1
	default:
		return 1
	}
}

func parseSourceFromText(text string) int {
	switch text {
	case "站点监测":
		return 1
	case "漏洞扫描":
		return 2
	case "流量分析":
		return 3
	case "风险探测":
		return 4
	default:
		return 2
	}
}

func parseFloat(s string) float64 {
	if s == "" {
		return 0
	}
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}
