package circular

import (
	transferContract "vulnscan-backend/circular/transfer/transfer-contract"

	"vulnscan-backend/circular/disposal"
	"vulnscan-backend/circular/distribute"
	"vulnscan-backend/circular/input"
	"vulnscan-backend/circular/ledger"
	"vulnscan-backend/circular/oplog"
	"vulnscan-backend/circular/review"
	"vulnscan-backend/circular/transfer"
	"vulnscan-backend/circular/verify"
	"vulnscan-backend/model"

	"code.yt-security.com/public/access/authorize"
	"code.yt-security.com/public/core/db"
	"github.com/gin-gonic/gin"
)

type Circular struct {
	inputHandler      *input.HandlerInput
	distributeHandler *distribute.HandlerDistribute
	verifyHandler     *verify.HandlerVerify
	disposalHandler   *disposal.HandlerDisposal
	reviewHandler     *review.HandlerReview
	ledgerHandler     *ledger.HandlerLedger
	oplogHandler      *oplog.HandlerOplog
	transferHandler   *transfer.HandlerTransfer
}

func NewCircular(
	inputHandler *input.HandlerInput,
	distributeHandler *distribute.HandlerDistribute,
	verifyHandler *verify.HandlerVerify,
	disposalHandler *disposal.HandlerDisposal,
	reviewHandler *review.HandlerReview,
	ledgerHandler *ledger.HandlerLedger,
	oplogHandler *oplog.HandlerOplog,
	transferHandler *transfer.HandlerTransfer,
	database *db.DB,
) *Circular {
	initModels(database)
	return &Circular{
		inputHandler:      inputHandler,
		distributeHandler: distributeHandler,
		verifyHandler:     verifyHandler,
		disposalHandler:   disposalHandler,
		reviewHandler:     reviewHandler,
		ledgerHandler:     ledgerHandler,
		oplogHandler:      oplogHandler,
		transferHandler:   transferHandler,
	}
}

func (m *Circular) TransferService() transferContract.ServiceTransfer {
	return m.transferHandler.TransferService()
}

func (m *Circular) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
	return authorize.RegisterRoutes(e.Group("/circular"), []authorize.Route{
		{
			Name: "通报列表", Path: "inputs", Enabled: true,
			Children: []authorize.Route{
				{Name: "录入列表", Method: "GET", Handler: m.inputHandler.List, Enabled: true},
				{Name: "录入创建", Method: "POST", Handler: m.inputHandler.Add, Enabled: true},
				{Name: "录入详情", Path: ":id", Method: "GET", Handler: m.inputHandler.Detail, Enabled: true},
				{Name: "录入编辑", Path: ":id", Method: "PUT", Handler: m.inputHandler.Edit, Enabled: true},
				{Name: "录入删除", Path: ":id", Method: "DELETE", Handler: m.inputHandler.Delete, Enabled: true},
				{Name: "提交核验", Path: ":id/submit", Method: "POST", Handler: m.inputHandler.Submit, Enabled: true},
				{Name: "导出通报", Path: "export", Method: "POST", Handler: m.inputHandler.Export, Enabled: true},
				{Name: "导入通报", Path: "import", Method: "POST", Handler: m.inputHandler.Import, Enabled: true},
				{Name: "下载模板", Path: "template/download", Method: "GET", Handler: m.inputHandler.CommonTemplateDownload, Enabled: true},
				{Name: "第三方导入", Path: "third-party", Method: "POST", Handler: m.inputHandler.ThirdPartyImport, Enabled: true},
			},
		},
		{
			Name: "通报核验", Path: "verifications", Enabled: true,
			Children: []authorize.Route{
				{Name: "核验列表", Method: "GET", Handler: m.verifyHandler.List, Enabled: true},
				{Name: "核验通报", Method: "POST", Handler: m.verifyHandler.Verify, Enabled: true},
			},
		},
		{
			Name: "通报派发", Path: "distributions", Enabled: true,
			Children: []authorize.Route{
				{Name: "派发列表", Method: "GET", Handler: m.distributeHandler.List, Enabled: true},
				{Name: "派发通报", Method: "POST", Handler: m.distributeHandler.Distribute, Enabled: true},
			},
		},
		{
			Name: "通报处置", Path: "disposals", Enabled: true,
			Children: []authorize.Route{
				{Name: "处置列表", Method: "GET", Handler: m.disposalHandler.List, Enabled: true},
				{Name: "处置通报", Path: ":id", Method: "POST", Handler: m.disposalHandler.Dispose, Enabled: true},
				{Name: "转派通报", Path: "redistribute", Method: "POST", Handler: m.disposalHandler.Redistribute, Enabled: true},
			},
		},
		{
			Name: "通报审核", Path: "reviews", Enabled: true,
			Children: []authorize.Route{
				{Name: "审核列表", Method: "GET", Handler: m.reviewHandler.List, Enabled: true},
				{Name: "审核通报", Path: ":id", Method: "POST", Handler: m.reviewHandler.Review, Enabled: true},
			},
		},
		{
			Name: "通报台账", Path: "ledgers", Enabled: true,
			Children: []authorize.Route{
				{Name: "台账列表", Method: "GET", Handler: m.ledgerHandler.List, Enabled: true},
				{Name: "台账详情", Path: ":id", Method: "GET", Handler: m.ledgerHandler.Detail, Enabled: true},
			},
		},
		{
			Name: "操作日志", Path: "oplogs", Enabled: true,
			Children: []authorize.Route{
				{Name: "通报操作日志", Path: ":id", Method: "GET", Handler: m.oplogHandler.ByCircularId, Enabled: true},
			},
		},
		{
			Name: "安全事件流转", Path: "transfers", Enabled: true,
			Children: []authorize.Route{
				{Name: "接收事件", Method: "POST", Handler: m.transferHandler.ReceiveIncident, Enabled: true},
				{Name: "批量接收", Path: "batch", Method: "POST", Handler: m.transferHandler.ReceiveIncidentBatch, Enabled: true},
				{Name: "流转状态", Path: "status", Method: "GET", Handler: m.transferHandler.GetTransferStatus, Enabled: true},
				{Name: "下载事件报告", Path: "reports/:id/:format", Method: "GET", Handler: m.transferHandler.DownloadIncidentReport, Enabled: true},
			},
		},
	})
}

func initModels(database *db.DB) {
	session, _ := database.GetDBSession()
	_ = session.AutoMigrate(
		&model.Circular{},
		&model.CircularDistribution{},
		&model.CircularDistributionClosure{},
		&model.CircularOrganizeStatus{},
		&model.CircularDisposal{},
		&model.CircularReview{},
		&model.CircularOperationLog{},
		&model.CircularTransferRecord{},
	)
}
