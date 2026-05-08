package review

import (
	reviewContract "vulnscan-backend/circular/review/review-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceReview,
	NewHandlerReview,
	wire.Bind(new(reviewContract.ServiceReview), new(*serviceReview)),
)
