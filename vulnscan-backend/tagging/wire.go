package tagging

import (
	tc "vulnscan-backend/tagging/tagging-contract"

	"github.com/google/wire"
)

var Set = wire.NewSet(
	NewServiceTag,
	wire.Bind(new(tc.ServiceTag), new(*serviceTag)),
	NewServiceChangeLog,
	wire.Bind(new(tc.ServiceChangeLog), new(*serviceChangeLog)),
	NewHandlerTag,
	NewHandlerChangeLog,
	NewTagging,
)
