package ledgerContract

import (
	"context"

	inputContract "vulnscan-backend/circular/input/input-contract"
)

type ServiceLedger interface {
	List(ctx context.Context, req inputContract.ListQuery) (int64, []inputContract.ListResp, error)
	Detail(ctx context.Context, id string) (*inputContract.InputDetailResp, error)
}
