package cluster

import (
	"vulnscan-backend/boot"
	"vulnscan-backend/pkg/clusterconn"
)

func ProvideClusterConnectivity(cfg *boot.Config) clusterconn.Options {
	return clusterconn.OptionsFromConfig(cfg)
}
