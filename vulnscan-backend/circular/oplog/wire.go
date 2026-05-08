package oplog

import (
	oplogContract "vulnscan-backend/circular/oplog/oplog-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceOplog,
	NewHandlerOplog,
	wire.Bind(new(oplogContract.ServiceOplog), new(*serviceOplog)),
)
