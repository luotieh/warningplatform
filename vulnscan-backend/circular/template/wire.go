package template

import (
	templateContract "vulnscan-backend/circular/template/template-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceTemplate,
	NewHandlerTemplate,
	wire.Bind(new(templateContract.ServiceTemplate), new(*serviceTemplate)),
)
