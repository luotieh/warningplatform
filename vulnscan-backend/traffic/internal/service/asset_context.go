package service

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"vulnscan-backend/traffic/internal/domain"
)

// AssetMatchContext 用事件涉及的地址（威胁侧/受害侧/报文双向）匹配资产清单，
// 生成注入 LLM prompt 的资产身份段落，供自动分析报告与工程师对话共用。
// 解决的问题：
//   - 被攻击资产只显示裸 IP，缺少资产清单中的名称/角色（如“内网DNS服务器”）；
//   - 威胁侧命中已登记资产（如内部 DNS 服务器被误标为攻击源）时给出复核警示。
//
// 只匹配启用（status=1）资产；返回空串表示无可用清单或事件无 IP 地址。
func (s Services) AssetMatchContext(event domain.Event) string {
	roles := eventAddressRoles(event)
	if len(roles) == 0 {
		return ""
	}
	assets := s.Store.ListAssets()
	if len(assets) == 0 {
		return ""
	}
	addrs := make([]string, 0, len(roles))
	for addr := range roles {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	var b strings.Builder
	threatMatched := []string{}
	for _, addr := range addrs {
		matched := matchRegistryAssets(assets, addr)
		roleText := strings.Join(roles[addr], "/")
		if len(matched) == 0 {
			fmt.Fprintf(&b, "- %s（%s）：未登记\n", addr, roleText)
			continue
		}
		for _, a := range matched {
			fmt.Fprintf(&b, "- %s（%s）：%s（%s）", addr, roleText, a.Name, a.Address)
			attrs := []string{}
			if a.AssetType != "" {
				attrs = append(attrs, "类型="+a.AssetType)
			}
			if a.Unit != "" {
				attrs = append(attrs, "单位="+a.Unit)
			}
			if a.Owner != "" {
				attrs = append(attrs, "责任人="+a.Owner)
			}
			if len(attrs) > 0 {
				b.WriteString("，" + strings.Join(attrs, "，"))
			}
			b.WriteString("\n")
		}
		if containsString(roles[addr], "威胁侧") {
			for _, a := range matched {
				threatMatched = append(threatMatched, fmt.Sprintf("%s「%s」", addr, a.Name))
			}
		}
	}
	if len(threatMatched) > 0 {
		fmt.Fprintf(&b, "注意：威胁侧地址 %s 命中了已登记资产。登记资产被标为威胁侧通常是方向误标（如 DNS 应答方向）或该资产被攻陷/滥用，必须结合 direction 与 DNS 查询/应答语义复核后再定性，禁止未经复核直接断言其为攻击发起方。\n", strings.Join(threatMatched, "、"))
	}
	return b.String()
}

// eventAddressRoles 汇总事件中各 IP 地址扮演的语义角色：
// 威胁侧/受害侧（semanticPeers 判定结果）与报文来源/报文目标（原始方向）。
// 域名等非 IP 值不参与资产匹配。
func eventAddressRoles(event domain.Event) map[string][]string {
	roles := map[string][]string{}
	add := func(addr, role string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return
		}
		addr = ip.Unmap().String()
		if !containsString(roles[addr], role) {
			roles[addr] = append(roles[addr], role)
		}
	}
	ctx := decodeEventContext(event.Context)
	add(asString(ctx["threat_source"]), "威胁侧")
	add(asString(ctx["victim_target"]), "受害侧")
	add(asString(ctx["src_ip"]), "报文来源")
	add(asString(ctx["dst_ip"]), "报文目标")
	for _, ob := range event.Observables {
		switch ob.Role {
		case "threat_source":
			add(ob.Value, "威胁侧")
		case "affected_asset":
			add(ob.Value, "受害侧")
		case "source":
			add(ob.Value, "报文来源")
		case "destination":
			add(ob.Value, "报文目标")
		}
	}
	return roles
}

// matchRegistryAssets 返回启用（status=1）且地址覆盖 ip 的资产：
// 精确匹配单 IP，或对 ip_segment/含“/”的地址按 CIDR 网段包含匹配。
func matchRegistryAssets(assets []domain.Asset, ip string) []domain.Asset {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	matched := []domain.Asset{}
	for _, a := range assets {
		if a.Status != 1 {
			continue
		}
		raw := strings.TrimSpace(a.Address)
		if raw == "" {
			continue
		}
		if a.AssetType == "ip_segment" || strings.Contains(raw, "/") {
			if prefix, err := netip.ParsePrefix(strings.ToLower(raw)); err == nil && prefix.Contains(addr) {
				matched = append(matched, a)
			}
			continue
		}
		if assetAddr, err := netip.ParseAddr(strings.ToLower(raw)); err == nil && assetAddr.Unmap() == addr {
			matched = append(matched, a)
		}
	}
	return matched
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
