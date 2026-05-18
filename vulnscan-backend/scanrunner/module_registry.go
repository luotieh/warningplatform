package scanrunner

import (
	"sort"
	"sync"

	"vulnscan-backend/scan/core"
)

type ModuleBuilder func(deps *ModuleDeps) core.ScanModule

type ModuleDeps struct {
	Factory *ModuleFactory
}

var (
	registryMu sync.RWMutex
	registry   = make(map[string]ModuleBuilder)
)

func RegisterModule(id string, builder ModuleBuilder) {
	registryMu.Lock()
	registry[id] = builder
	registryMu.Unlock()
}

func GetModuleBuilder(id string) (ModuleBuilder, bool) {
	registryMu.RLock()
	b, ok := registry[id]
	registryMu.RUnlock()
	return b, ok
}

func RegisteredModuleIDs() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
