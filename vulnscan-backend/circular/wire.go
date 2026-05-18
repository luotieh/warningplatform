package circular

import (
	"vulnscan-backend/circular/disposal"
	"vulnscan-backend/circular/distribute"
	"vulnscan-backend/circular/input"
	"vulnscan-backend/circular/ledger"
	"vulnscan-backend/circular/oplog"
	"vulnscan-backend/circular/review"
	"vulnscan-backend/circular/transfer"
	"vulnscan-backend/circular/verify"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	input.WireSet,
	distribute.WireSet,
	verify.WireSet,
	disposal.WireSet,
	review.WireSet,
	ledger.WireSet,
	oplog.WireSet,
	transfer.WireSet,
	NewCircular,
)
