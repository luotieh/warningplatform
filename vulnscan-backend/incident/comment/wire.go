package comment

import (
	commentContract "vulnscan-backend/incident/comment/comment-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceComment,
	NewHandlerComment,
	wire.Bind(new(commentContract.ServiceComment), new(*serviceComment)),
)
