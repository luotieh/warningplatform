package asset

import (
	"strings"

	"vulnscan-backend/model"
)

// normalizeAssetAddressFields 保证 address 有值，与列表/编辑展示一致（address 为空时回退 domain/ipv4/ipv6）。
func normalizeAssetAddressFields(item *model.Asset) {
	if item == nil {
		return
	}
	item.Address = strings.TrimSpace(item.Address)
	item.Domain = strings.TrimSpace(item.Domain)
	item.IPv4 = strings.TrimSpace(item.IPv4)
	item.IPv6 = strings.TrimSpace(item.IPv6)
	if item.Address != "" {
		return
	}
	switch {
	case item.Domain != "":
		item.Address = item.Domain
	case item.IPv4 != "":
		item.Address = item.IPv4
	case item.IPv6 != "":
		item.Address = item.IPv6
	}
}
