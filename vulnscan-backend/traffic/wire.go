package traffic

import "github.com/google/wire"

var WireSet = wire.NewSet(NewTraffic)
