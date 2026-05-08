package disposalContract

import (
	"vulnscan-backend/model"

	distributeContract "vulnscan-backend/circular/distribute/distribute-contract"
	inputContract "vulnscan-backend/circular/input/input-contract"

	"github.com/gin-gonic/gin"
)

type DisposalCondition struct {
	DisposalResult   string             `json:"disposal_result"`
	DisposalQuestion string             `json:"disposal_question"`
	DisposalData     model.JSONMapSlice `json:"disposal_data"`
}

type ServiceDisposal interface {
	List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error)
	Dispose(c *gin.Context, id string, userId string, req DisposalCondition) error
	Redistribute(c *gin.Context, req distributeContract.RedistributeReq, userId string) error
}
