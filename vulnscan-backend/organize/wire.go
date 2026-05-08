package organize

import (
	oc "vulnscan-backend/organize/organize-contract"

	"github.com/google/wire"
)

var Set = wire.NewSet(
	NewServiceOrganize,
	wire.Bind(new(oc.ServiceOrganize), new(*serviceOrganize)),
	NewServiceConstruction,
	wire.Bind(new(oc.ServiceConstruction), new(*serviceConstruction)),
	NewHandlerOrganize,
	NewHandlerConstruction,
	NewOrganize,
)
