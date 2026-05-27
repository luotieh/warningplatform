package organize

import (
	"context"
	"fmt"

	"code.yt-security.com/public/sdk/identity"
)

const iamOrganizeListPageSize = 100

// ListAllIAMOrganizes 分页拉取 IAM 全部组织（供精确按名匹配，避免 Options 关键词检索漏项）。
func ListAllIAMOrganizes(ctx context.Context, svc *identity.OrganizeAdminService) ([]*identity.OrganizeInfo, error) {
	return listAllIAMOrganizes(ctx, svc)
}

// listAllIAMOrganizes 分页拉取 IAM 组织（避免 SDK GetOrganizeTree 使用 size=9999 触发校验失败）。
func listAllIAMOrganizes(ctx context.Context, svc *identity.OrganizeAdminService) ([]*identity.OrganizeInfo, error) {
	if svc == nil {
		return nil, fmt.Errorf("iam organize service not initialized")
	}

	var all []*identity.OrganizeInfo
	for page := 1; ; page++ {
		list, err := svc.ListOrganizes(ctx, identity.OrganizeQuery{
			Index: page,
			Size:  iamOrganizeListPageSize,
		})
		if err != nil {
			return nil, err
		}
		if len(list.Items) == 0 {
			break
		}
		all = append(all, list.Items...)
		if len(list.Items) < iamOrganizeListPageSize {
			break
		}
		if list.Total > 0 && int64(len(all)) >= list.Total {
			break
		}
	}
	return all, nil
}
