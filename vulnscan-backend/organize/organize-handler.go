package organize

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/model"
	oc "vulnscan-backend/organize/organize-contract"

	"code.yt-security.com/public/core/v2/web"
	iamsdk "code.yt-security.com/public/sdk"
	"code.yt-security.com/public/sdk/identity"
	iamsdk_middleware "code.yt-security.com/public/sdk/middleware"
	"code.yt-security.com/public/sdk/permission"
	"code.yt-security.com/public/sdk/transport"
	"github.com/gin-gonic/gin"
)

// HandlerOrganize 组织管理 HTTP Handler
type HandlerOrganize struct {
	svc oc.ServiceOrganize
	iam *iamsdk.Client
}

func NewHandlerOrganize(svc oc.ServiceOrganize, iam *iamsdk.Client) *HandlerOrganize {
	return &HandlerOrganize{svc: svc, iam: iam}
}

func (h *HandlerOrganize) List(c *gin.Context) {
	req, ok := web.BindQuery[oc.OrganizeListReq](c)
	if !ok {
		return
	}
	items, err := h.svc.Tree()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	filtered := h.filterOrganizesByPermission(c, items, false)
	if req.Name != "" {
		filtered = filterOrganizesByName(filtered, req.Name)
	}

	count := int64(len(filtered))
	page, pageSize := normalizeOrganizePage(req.Page, req.PageSize, req.Name != "")
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		web.OK(c).List(count, []model.Organize{}).Send()
		return
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	web.OK(c).List(count, filtered[start:end]).Send()
}

func (h *HandlerOrganize) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}

	allowed, err := h.canAccessOrganize(c, uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if !allowed {
		web.R(c).Code(web.Failed).HTTP(http.StatusForbidden).Msg("permission denied").Send()
		return
	}

	id := uri.Id
	item, err := h.svc.GetByID(id)
	if err != nil {
		if fallback := h.organizeFromIAM(c, id); fallback != nil {
			web.OK(c).Data(fallback).Send()
			return
		}
		web.Err(c, web.NotFound).Send()
		return
	}
	h.mergeOrganizeFromIAM(c, item)
	web.OK(c).Data(item).Send()
}

func (h *HandlerOrganize) Create(c *gin.Context) {
	var item model.Organize
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := h.ensureIAMOrganizeForCreate(c, &item, user.OrganizeID); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	NormalizeOrganizeAddress(&item)
	if err := validateOrganizeItem(&item); err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerOrganize) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	allowed, err := h.canAccessOrganize(c, uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if !allowed {
		web.R(c).Code(web.Failed).HTTP(http.StatusForbidden).Msg("permission denied").Send()
		return
	}

	NormalizeOrganizeUpdates(body)
	if err := validateOrganizeUpdates(body); err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	if err := h.svc.Update(uri.Id, body); err != nil {
		web.Fail(c).Msg(userFacingOrganizeError(err)).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerOrganize) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}

	allowed, err := h.canAccessOrganize(c, uri.Id)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	if !allowed {
		web.R(c).Code(web.Failed).HTTP(http.StatusForbidden).Msg("permission denied").Send()
		return
	}

	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerOrganize) Ensure(c *gin.Context) {
	req, ok := web.BindJSON[oc.EnsureOrganizeReq](c)
	if !ok {
		return
	}
	h.enrichEnsureReqFromIAM(c, &req)
	item, err := h.svc.Ensure(req)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerOrganize) Tree(c *gin.Context) {
	items, err := h.svc.Tree()
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	filtered := h.filterOrganizesByPermission(c, items, true)
	web.OK(c).Data(buildOrganizeTreeFromFlat(filtered)).Send()
}

func (h *HandlerOrganize) IAMTree(c *gin.Context) {
	nodes, err := h.fetchIAMOrganizeTree(c)
	if err != nil {
		if isIAMUnauthorized(err) {
			web.R(c).Code(web.Failed).HTTP(http.StatusUnauthorized).Msg("authentication expired, please login again").Send()
			return
		}
		web.Fail(c).Msg("fetch IAM organizes failed: " + err.Error()).Send()
		return
	}
	web.OK(c).Data(convertIAMNodes(nodes)).Send()
}

func (h *HandlerOrganize) SyncIam(c *gin.Context) {
	nodes, err := h.fetchIAMOrganizeTree(c)
	if err != nil {
		if isIAMUnauthorized(err) {
			web.R(c).Code(web.Failed).HTTP(http.StatusUnauthorized).Msg("authentication expired, please login again").Send()
			return
		}
		web.Fail(c).Msg("fetch IAM organizes failed: " + err.Error()).Send()
		return
	}

	iamNodes := convertIAMNodes(nodes)
	count, err := h.svc.SyncFromIAM(iamNodes)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(gin.H{
		"synced": count,
		"total":  countOrganizeNodes(iamNodes),
	}).Send()
}

func (h *HandlerOrganize) fetchIAMOrganizeTree(c *gin.Context) ([]*identity.OrganizeNode, error) {
	if h.iam == nil {
		return nil, fmt.Errorf("iam client not initialized")
	}
	userCtx, userCancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer userCancel()

	infos, err := listAllIAMOrganizes(userCtx, h.iam.Organize)
	if err != nil && isIAMUnauthorized(err) {
		serviceCtx, serviceCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer serviceCancel()
		infos, err = listAllIAMOrganizes(serviceCtx, h.iam.Organize)
	}
	if err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		infos, err = h.fetchIAMOrganizeInfos(userCtx)
		if err != nil {
			return nil, err
		}
	}
	return buildIAMOrganizeTree(infos), nil
}

func (h *HandlerOrganize) fetchIAMOrganizeInfos(ctx context.Context) ([]*identity.OrganizeInfo, error) {
	options, err := h.iam.Organize.GetOrganizeOptions(ctx, "")
	if err != nil {
		return nil, err
	}
	infos := make([]*identity.OrganizeInfo, 0, len(options))
	seen := make(map[string]struct{}, len(options))
	for _, option := range options {
		if option.ID == "" {
			continue
		}
		if _, exists := seen[option.ID]; exists {
			continue
		}
		info, err := h.iam.Organize.GetOrganize(ctx, option.ID)
		if err != nil {
			return nil, err
		}
		if info == nil {
			continue
		}
		seen[info.ID] = struct{}{}
		infos = append(infos, info)
	}
	return infos, nil
}

func (h *HandlerOrganize) enrichEnsureReqFromIAM(c *gin.Context, req *oc.EnsureOrganizeReq) {
	if req == nil || req.ID == "" || h.iam == nil {
		return
	}
	info, err := h.iam.Organize.GetOrganize(c.Request.Context(), req.ID)
	if err != nil || info == nil {
		return
	}
	if req.Name == "" {
		req.Name = info.Name
	}
	if req.ParentID == "" {
		req.ParentID = info.ParentID
	}
	if req.UnifiedSocialCreditCode == "" {
		req.UnifiedSocialCreditCode = info.CreditCode
	}
}

func (h *HandlerOrganize) filterOrganizesByPermission(c *gin.Context, items []model.Organize, includeAncestors bool) []model.Organize {
	visibleIDs := resolveVisibleOrganizeIDs(c, items)
	if len(visibleIDs) == 0 {
		return []model.Organize{}
	}

	if includeAncestors {
		parentMap := make(map[string]string, len(items))
		for _, item := range items {
			parentMap[item.ID] = item.ParentID
		}
		for id := range visibleIDs {
			currentID := id
			for currentID != "" {
				parentID := parentMap[currentID]
				if parentID == "" {
					break
				}
				if _, exists := visibleIDs[parentID]; exists {
					break
				}
				visibleIDs[parentID] = struct{}{}
				currentID = parentID
			}
		}
	}

	filtered := make([]model.Organize, 0, len(visibleIDs))
	for _, item := range items {
		if _, ok := visibleIDs[item.ID]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func resolveVisibleOrganizeIDs(c *gin.Context, items []model.Organize) map[string]struct{} {
	user, ok := iamsdk.GetCurrentUser(c)
	if !ok || user == nil {
		return map[string]struct{}{}
	}

	scope, hasScope := iamsdk.GetDataScope(c)
	if !hasScope || scope == nil {
		// 单位管理页需展示完整组织树；未配置数据范围时默认可见全部（与资产数据权限分离）。
		scope = &iamsdk_middleware.DataScope{
			Scope:       permission.ScopeAll,
			OrganizeIDs: nil,
		}
	}

	if scope.Scope == permission.ScopeAll {
		all := make(map[string]struct{}, len(items))
		for _, item := range items {
			all[item.ID] = struct{}{}
		}
		return all
	}

	childMap := make(map[string][]string, len(items))
	for _, item := range items {
		if item.ParentID == "" {
			continue
		}
		childMap[item.ParentID] = append(childMap[item.ParentID], item.ID)
	}

	visible := make(map[string]struct{})
	addVisible := func(id string) {
		if id != "" {
			visible[id] = struct{}{}
		}
	}
	addDescendants := func(rootID string) {}
	addDescendants = func(rootID string) {
		for _, childID := range childMap[rootID] {
			if _, exists := visible[childID]; exists {
				continue
			}
			visible[childID] = struct{}{}
			addDescendants(childID)
		}
	}

	switch scope.Scope {
	case permission.ScopeOrganize:
		for _, id := range scope.OrganizeIDs {
			addVisible(id)
		}
		addVisible(user.OrganizeID)
	case permission.ScopeOrganizeSub:
		for _, id := range scope.OrganizeIDs {
			addVisible(id)
			addDescendants(id)
		}
		addVisible(user.OrganizeID)
		addDescendants(user.OrganizeID)
	case permission.ScopeDepartment, permission.ScopeDepartmentSub, permission.ScopeSelf:
		addVisible(user.OrganizeID)
	default:
		addVisible(user.OrganizeID)
	}

	return visible
}

func filterOrganizesByName(items []model.Organize, keyword string) []model.Organize {
	keyword = strings.TrimSpace(strings.ToLower(keyword))
	if keyword == "" {
		return items
	}

	filtered := make([]model.Organize, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Name), keyword) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func normalizePage(page, pageSize int) (int, int) {
	return normalizeOrganizePage(page, pageSize, false)
}

func normalizeOrganizePage(page, pageSize int, searching bool) (int, int) {
	if page < 1 {
		page = 1
	}
	maxSize := 100
	if searching {
		maxSize = 200
	}
	if pageSize < 1 {
		pageSize = 20
	} else if pageSize > maxSize {
		pageSize = maxSize
	}
	return page, pageSize
}

func (h *HandlerOrganize) canAccessOrganize(c *gin.Context, id string) (bool, error) {
	if id == "" {
		return false, nil
	}

	items, err := h.svc.Tree()
	if err != nil {
		return false, err
	}

	visibleIDs := resolveVisibleOrganizeIDs(c, items)
	_, allowed := visibleIDs[id]
	return allowed, nil
}

func (h *HandlerOrganize) ensureIAMOrganizeForCreate(c *gin.Context, item *model.Organize, defaultParentID string) error {
	if item == nil || h.iam == nil {
		return nil
	}
	if item.ID != "" || item.Name == "" {
		return nil
	}

	info, err := h.findIAMOrganizeByName(c, item.Name)
	if err != nil {
		return err
	}
	if info == nil {
		req := &identity.CreateOrganizeRequest{
			Name:       item.Name,
			ParentID:   firstNonEmpty(item.ParentID, defaultParentID),
			CreditCode: item.UnifiedSocialCreditCode,
		}
		info, err = h.iam.Organize.CreateOrganize(c.Request.Context(), req)
		if err != nil {
			return fmt.Errorf("create IAM organize failed: %w", err)
		}
	}

	item.ID = info.ID
	item.Name = firstNonEmpty(info.Name, item.Name)
	item.ParentID = firstNonEmpty(info.ParentID, item.ParentID)
	item.UnifiedSocialCreditCode = firstNonEmpty(info.CreditCode, item.UnifiedSocialCreditCode)
	return nil
}

func (h *HandlerOrganize) findIAMOrganizeByName(c *gin.Context, name string) (*identity.OrganizeInfo, error) {
	if h.iam == nil || name == "" {
		return nil, nil
	}
	info, err := FindIAMOrganizeByExactName(c.Request.Context(), h.iam.Organize, name)
	if err != nil {
		return nil, fmt.Errorf("query IAM organize failed: %w", err)
	}
	return info, nil
}

func (h *HandlerOrganize) organizeFromIAM(c *gin.Context, id string) *model.Organize {
	if id == "" || h.iam == nil {
		return nil
	}
	info, err := h.iam.Organize.GetOrganize(c.Request.Context(), id)
	if err != nil || info == nil {
		return nil
	}
	return organizeModelFromIAM(info)
}

func (h *HandlerOrganize) mergeOrganizeFromIAM(c *gin.Context, item *model.Organize) {
	if item == nil || h.iam == nil {
		return
	}
	if item.Name != "" && item.ParentID != "" && item.UnifiedSocialCreditCode != "" {
		return
	}
	info, err := h.iam.Organize.GetOrganize(c.Request.Context(), item.ID)
	if err != nil || info == nil {
		return
	}

	updates := map[string]interface{}{}
	if item.Name == "" && info.Name != "" {
		item.Name = info.Name
		updates["name"] = info.Name
	}
	if item.ParentID == "" && info.ParentID != "" {
		item.ParentID = info.ParentID
		updates["parent_id"] = info.ParentID
	}
	if item.UnifiedSocialCreditCode == "" && info.CreditCode != "" {
		item.UnifiedSocialCreditCode = info.CreditCode
		updates["unified_social_credit_code"] = info.CreditCode
	}
	if len(updates) == 0 {
		return
	}
	_ = h.svc.Update(item.ID, updates)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func isIAMUnauthorized(err error) bool {
	var iamErr *transport.IAMResponseError
	return errors.As(err, &iamErr) && iamErr.IsUnauthorized()
}

func organizeModelFromIAM(info *identity.OrganizeInfo) *model.Organize {
	if info == nil {
		return nil
	}
	return &model.Organize{
		ID:                      info.ID,
		Name:                    info.Name,
		ParentID:                info.ParentID,
		UnifiedSocialCreditCode: info.CreditCode,
	}
}

func buildIAMOrganizeTree(items []*identity.OrganizeInfo) []*identity.OrganizeNode {
	nodeMap := make(map[string]*identity.OrganizeNode, len(items))
	for _, item := range items {
		if item == nil || item.ID == "" {
			continue
		}
		nodeMap[item.ID] = &identity.OrganizeNode{
			ID:       item.ID,
			Name:     item.Name,
			ParentID: item.ParentID,
			Sort:     item.Sort,
			Status:   item.Status,
		}
	}

	roots := make([]*identity.OrganizeNode, 0)
	for _, item := range items {
		if item == nil || item.ID == "" {
			continue
		}
		node := nodeMap[item.ID]
		if node == nil {
			continue
		}
		if item.ParentID != "" {
			if parent, ok := nodeMap[item.ParentID]; ok {
				parent.Children = append(parent.Children, node)
				continue
			}
		}
		roots = append(roots, node)
	}
	return roots
}

func convertIAMNodes(nodes []*identity.OrganizeNode) []*oc.OrganizeNode {
	if nodes == nil {
		return nil
	}
	result := make([]*oc.OrganizeNode, len(nodes))
	for i, n := range nodes {
		result[i] = &oc.OrganizeNode{
			ID:       n.ID,
			Name:     n.Name,
			ParentID: n.ParentID,
			Sort:     n.Sort,
			Status:   n.Status,
			Children: convertIAMNodes(n.Children),
		}
	}
	return result
}

func countOrganizeNodes(nodes []*oc.OrganizeNode) int {
	total := 0
	var walk func([]*oc.OrganizeNode)
	walk = func(items []*oc.OrganizeNode) {
		for _, item := range items {
			if item == nil {
				continue
			}
			total++
			if len(item.Children) > 0 {
				walk(item.Children)
			}
		}
	}
	walk(nodes)
	return total
}

// HandlerConstruction 单位补充信息 HTTP Handler
type HandlerConstruction struct {
	svc oc.ServiceConstruction
}

func NewHandlerConstruction(svc oc.ServiceConstruction) *HandlerConstruction {
	return &HandlerConstruction{svc: svc}
}

func (h *HandlerConstruction) List(c *gin.Context) {
	req, ok := web.BindQuery[oc.ConstructionListReq](c)
	if !ok {
		return
	}
	scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
	items, count, err := h.svc.List(req, scope)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).List(count, items).Send()
}

func (h *HandlerConstruction) GetByID(c *gin.Context) {
	item, err := h.svc.GetByID(c.Param("id"))
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerConstruction) Create(c *gin.Context) {
	var item model.ConstructionOrg
	if !web.ValidationJson(c, &item) {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item.CreatedBy = user.UserID
	if err := validateConstructionOrg(&item); err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	if err := h.svc.Create(&item); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Data(item).Send()
}

func (h *HandlerConstruction) Update(c *gin.Context) {
	id := c.Param("id")
	body, ok := web.BindJSON[map[string]interface{}](c)
	if !ok {
		return
	}
	if err := validateConstructionUpdates(body); err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}
	if err := h.svc.Update(id, body); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}

func (h *HandlerConstruction) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Param("id")); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.OK(c).Send()
}
