package transfer

import (
	transferContract "vulnscan-backend/circular/transfer/transfer-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceTransfer,
	NewHandlerTransfer,
	wire.Bind(new(transferContract.ServiceTransfer), new(*serviceTransfer)),
)
