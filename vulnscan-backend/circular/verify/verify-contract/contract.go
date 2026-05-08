package verifyContract

import (
	"context"

	inputContract "vulnscan-backend/circular/input/input-contract"
)

type VerifyReq struct {
	CircularIds []string `json:"circular_ids" binding:"required"`
	Result      string   `json:"result" binding:"required"`
}

type ServiceVerify interface {
	List(ctx context.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error)
	Verify(ctx context.Context, req VerifyReq, userId string) error
}
