package reviewContract

import (
	inputContract "vulnscan-backend/circular/input/input-contract"

	"github.com/gin-gonic/gin"
)

type ReviewCondition struct {
	Review       string `json:"review" binding:"required"`
	Instructions string `json:"instructions"`
	Annex        string `json:"annex"`
}

type ServiceReview interface {
	List(c *gin.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error)
	Review(c *gin.Context, id string, userId string, req ReviewCondition) error
}
