package transfer

import (
	"fmt"
	"net/http"
	"strings"

	"vulnscan-backend/circular/scope"
	transferContract "vulnscan-backend/circular/transfer/transfer-contract"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerTransfer struct {
	svc transferContract.ServiceTransfer
}

func NewHandlerTransfer(svc transferContract.ServiceTransfer) *HandlerTransfer {
	return &HandlerTransfer{svc: svc}
}

func (h *HandlerTransfer) TransferService() transferContract.ServiceTransfer {
	return h.svc
}

func (h *HandlerTransfer) ReceiveIncident(c *gin.Context) {
	req, ok := web.BindJSON[transferContract.TransferIncidentReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	code, err := h.svc.ReceiveIncident(c.Request.Context(), req, scope.ActorFromContext(c), user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(map[string]string{"circular_code": code}).Send()
}

func (h *HandlerTransfer) ReceiveIncidentBatch(c *gin.Context) {
	req, ok := web.BindJSON[transferContract.TransferIncidentBatchReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	results, err := h.svc.ReceiveIncidentBatch(c.Request.Context(), req, scope.ActorFromContext(c), user.OrganizeID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(results).Send()
}

func (h *HandlerTransfer) DownloadIncidentReport(c *gin.Context) {
	uri, ok := web.BindUri[struct {
		Id     string `uri:"id"`
		Format string `uri:"format"`
	}](c)
	if !ok {
		return
	}
	raw, filename, err := h.svc.ExportCircularIncidentReport(c.Request.Context(), uri.Id, uri.Format)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	ctype, disp := reportContentHeaders(filename, uri.Format)
	c.Header("Content-Type", ctype)
	c.Header("Content-Disposition", disp)
	c.Data(http.StatusOK, ctype, raw)
}

func reportContentHeaders(filename, format string) (string, string) {
	format = strings.ToLower(format)
	if format == "word" {
		format = "docx"
	}
	switch format {
	case "docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			fmt.Sprintf("attachment; filename=%s", filename)
	case "pdf":
		return "application/pdf", fmt.Sprintf("attachment; filename=%s", filename)
	default:
		return "application/octet-stream", fmt.Sprintf("attachment; filename=%s", filename)
	}
}

func (h *HandlerTransfer) GetTransferStatus(c *gin.Context) {
	req, ok := web.BindQuery[struct {
		IncidentNo string `form:"incident_no" binding:"required"`
	}](c)
	if !ok {
		return
	}
	resp, err := h.svc.GetTransferStatus(c.Request.Context(), req.IncidentNo)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(resp).Send()
}
