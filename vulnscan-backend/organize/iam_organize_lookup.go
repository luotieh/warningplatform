package organize

import (
	"context"
	"strings"

	"code.yt-security.com/public/sdk/identity"
)

// FindIAMOrganizeByExactName 按名称精确匹配 IAM 组织（同名取第一条，避免重复创建）。
func FindIAMOrganizeByExactName(ctx context.Context, svc *identity.OrganizeService, name string) (*identity.OrganizeInfo, error) {
	name = strings.TrimSpace(name)
	if name == "" || svc == nil {
		return nil, nil
	}

	all, err := ListAllIAMOrganizes(ctx, svc)
	if err != nil {
		return findIAMOrganizeByOptions(ctx, svc, name)
	}
	var matched *identity.OrganizeInfo
	for _, info := range all {
		if info == nil || strings.TrimSpace(info.Name) != name {
			continue
		}
		if matched == nil {
			matched = info
			continue
		}
		// 已存在同名组织，不再创建新的；沿用最先匹配到的一条。
	}
	return matched, nil
}

func findIAMOrganizeByOptions(ctx context.Context, svc *identity.OrganizeService, name string) (*identity.OrganizeInfo, error) {
	options, err := svc.GetOrganizeOptions(ctx, name)
	if err != nil {
		return nil, err
	}
	for _, option := range options {
		if strings.TrimSpace(option.Name) != name {
			continue
		}
		info, err := svc.GetOrganize(ctx, option.ID)
		if err != nil {
			return nil, err
		}
		return info, nil
	}
	return nil, nil
}
