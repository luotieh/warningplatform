package ledgerContract

import (
	inputContract "vulnscan-backend/circular/input/input-contract"

	"github.com/gin-gonic/gin"
)

type ServiceLedger interface {
	List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error)
	Detail(c *gin.Context, id string) (*inputContract.InputDetailResp, error)
}
