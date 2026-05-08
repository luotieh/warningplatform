package input

import (
	inputContract "vulnscan-backend/circular/input/input-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceInput,
	NewHandlerInput,
	wire.Bind(new(inputContract.ServiceInput), new(*serviceInput)),
)
