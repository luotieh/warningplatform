package distributeContract

import (
	"vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	inputContract "vulnscan-backend/circular/input/input-contract"

	"github.com/gin-gonic/gin"
)

type DistributeReq struct {
	CircularId         string             `json:"circular_id" binding:"required"`
	TargetOrganize     string             `json:"target_organize" binding:"required"`
	ProcessingDeadline string             `json:"processing_deadline"`
	Requirements       string             `json:"requirements"`
	DisposalTemplate   string             `json:"disposal_template"`
	DisposalData       model.JSONMapSlice `json:"disposal_data"`
}

type RedistributeReq struct {
	CircularId         string `json:"circular_id" binding:"required"`
	DistributionId     string `json:"distribution_id" binding:"required"`
	TargetOrganize     string `json:"target_organize" binding:"required"`
	ProcessingDeadline string `json:"processing_deadline"`
	Requirements       string `json:"requirements"`
}

type ServiceDistribute interface {
	List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error)
	Distribute(c *gin.Context, req DistributeReq, actor scope.Actor) error
}
