package oplogContract

import (
	"context"
	"vulnscan-backend/model"
)

type ServiceOplog interface {
	ByCircularId(ctx context.Context, circularId string) ([]model.CircularOperationLog, error)
}
