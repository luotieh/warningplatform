package cluster

import (
	clusterContract "vulnscan-backend/cluster/cluster-contract"

	"github.com/google/wire"
)

var WireSet = wire.NewSet(
	NewServiceCluster,
	NewHandlerCluster,
	NewCluster,
	wire.Bind(new(clusterContract.ServiceCluster), new(*serviceCluster)),
)
