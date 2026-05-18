package organize

import (
	"strings"

	"vulnscan-backend/model"
	oc "vulnscan-backend/organize/organize-contract"
)

// buildOrganizeTreeFromFlat 将带 parent_id 的扁平组织列表组装为树形结构。
func buildOrganizeTreeFromFlat(items []model.Organize) []*oc.OrganizeNode {
	if len(items) == 0 {
		return nil
	}
	nodeMap := make(map[string]*oc.OrganizeNode, len(items))
	for _, item := range items {
		if item.ID == "" {
			continue
		}
		nodeMap[item.ID] = &oc.OrganizeNode{
			ID:       item.ID,
			Name:     item.Name,
			ParentID: item.ParentID,
		}
	}

	roots := make([]*oc.OrganizeNode, 0)
	for _, item := range items {
		node := nodeMap[item.ID]
		if node == nil {
			continue
		}
		parentID := strings.TrimSpace(item.ParentID)
		if parentID != "" {
			if parent, ok := nodeMap[parentID]; ok {
				parent.Children = append(parent.Children, node)
				continue
			}
		}
		roots = append(roots, node)
	}
	return roots
}
