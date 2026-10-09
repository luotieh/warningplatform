package service

import (
	"sort"
	"vulnscan-backend/evidence"
)

// Port sequences and DNS/connection correlations must span endpoints. This
// aggregate reuses committed observations; it never changes their hit identity
// or mixes periodic time series across destinations.
func buildSnapshotAssetInputs(req *evidence.Request) {
	inputs := map[evidence.Scope]*evidence.Input{}
	for _, source := range req.Inputs {
		scope := evidence.Scope{AssetID: source.Scope.AssetID, EndpointID: "asset://" + source.Scope.AssetID, DeviceID: source.Scope.DeviceID}
		target := inputs[scope]
		if target == nil {
			target = &evidence.Input{Scope: scope}
			inputs[scope] = target
		}
		if source.Window != nil {
			if target.Window == nil {
				copy := *source.Window
				target.Window = &copy
			} else {
				if source.Window.Start.Before(target.Window.Start) {
					target.Window.Start = source.Window.Start
				}
				if source.Window.End.After(target.Window.End) {
					target.Window.End = source.Window.End
				}
			}
		}
		if source.Network != nil {
			if target.Network == nil {
				target.Network = &evidence.NetworkData{Provenance: evidence.Provenance{Verified: true, Complete: req.Quality.Coverage == evidence.CoverageComplete, Version: source.Network.Version}}
			}
			target.Network.Connections = append(target.Network.Connections, source.Network.Connections...)
			target.Network.SourceIDs = append(target.Network.SourceIDs, source.Network.SourceIDs...)
		}
		if source.DNS != nil {
			if target.DNS == nil {
				target.DNS = &evidence.DNSData{Provenance: evidence.Provenance{Verified: true, Complete: true, Version: source.DNS.Version}}
			}
			target.DNS.Complete = target.DNS.Complete && source.DNS.Complete
			target.DNS.Records = append(target.DNS.Records, source.DNS.Records...)
			target.DNS.SourceIDs = append(target.DNS.SourceIDs, source.DNS.SourceIDs...)
		}
	}
	for _, input := range inputs {
		req.AssetInputs = append(req.AssetInputs, *input)
	}
	sort.Slice(req.AssetInputs, func(i, j int) bool { return scopeKey(req.AssetInputs[i].Scope) < scopeKey(req.AssetInputs[j].Scope) })
}
