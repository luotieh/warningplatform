package engine

import (
	"net"
	"sort"
	"strings"
)

type TargetPartition struct {
	Key     string    `json:"key"`
	Targets []*Target `json:"targets"`
}

func PartitionTargets(targets []*Target, maxPerPartition int) []TargetPartition {
	if maxPerPartition <= 0 {
		maxPerPartition = 256
	}

	groups := make(map[string][]*Target)

	for _, t := range targets {
		key := classifyTarget(t)
		groups[key] = append(groups[key], t)
	}

	var partitions []TargetPartition
	for key, group := range groups {
		if len(group) <= maxPerPartition {
			partitions = append(partitions, TargetPartition{Key: key, Targets: group})
			continue
		}
		for i := 0; i < len(group); i += maxPerPartition {
			end := i + maxPerPartition
			if end > len(group) {
				end = len(group)
			}
			partitions = append(partitions, TargetPartition{
				Key:     key + "/" + string(rune('A'+i/maxPerPartition)),
				Targets: group[i:end],
			})
		}
	}

	sort.Slice(partitions, func(i, j int) bool {
		return len(partitions[i].Targets) > len(partitions[j].Targets)
	})

	return partitions
}

func classifyTarget(t *Target) string {
	addr := t.IP
	if addr == "" {
		addr = t.Host
	}
	if addr == "" {
		return "unknown"
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		parts := strings.Split(addr, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return addr
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4[:3].String() + ".0/24"
	}

	return ip.String()[:19] + "::/64"
}

func PartitionByProtocol(targets []*Target) map[string][]*Target {
	groups := make(map[string][]*Target)
	for _, t := range targets {
		proto := t.Protocol
		if proto == "" {
			proto = "tcp"
		}
		groups[proto] = append(groups[proto], t)
	}
	return groups
}
