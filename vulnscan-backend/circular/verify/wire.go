package verify

import (
	verifyContract "vulnscan-backend/circular/verify/verify-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceVerify,
	NewHandlerVerify,
	wire.Bind(new(verifyContract.ServiceVerify), new(*serviceVerify)),
)
