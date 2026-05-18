package organize

import (
	"context"
	"fmt"

	"code.yt-security.com/public/sdk/identity"
)

const iamOrganizeListPageSize = 100

// listAllIAMOrganizes 分页拉取 IAM 组织（避免 SDK GetOrganizeTree 使用 size=9999 触发校验失败）。
func listAllIAMOrganizes(ctx context.Context, svc *identity.OrganizeService) ([]*identity.OrganizeInfo, error) {
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
