package ledger

import (
	inputContract "vulnscan-backend/circular/input/input-contract"
	ledgerContract "vulnscan-backend/circular/ledger/ledger-contract"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

type HandlerLedger struct {
	svc ledgerContract.ServiceLedger
}

func NewHandlerLedger(svc ledgerContract.ServiceLedger) *HandlerLedger {
	return &HandlerLedger{svc: svc}
}

func (h *HandlerLedger) List(c *gin.Context) {
	req, ok := web.BindQuery[inputContract.ListQuery](c)
	if !ok {
		return
	}
	total, items, err := h.svc.List(c, req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(total, items).Send()
}

func (h *HandlerLedger) Detail(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.Detail(c, uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}
