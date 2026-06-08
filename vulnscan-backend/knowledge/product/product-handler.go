package product

import (
	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

type HandlerProduct struct {
	svc *ServiceProduct
}

func NewHandlerProduct(svc *ServiceProduct) *HandlerProduct {
	return &HandlerProduct{svc: svc}
}

func (h *HandlerProduct) List(c *gin.Context) {
	query, ok := web.BindQuery[ProductQuery](c)
	if !ok {
		return
	}
	items, count, err := h.svc.List(query)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}

	productIDs := make([]string, 0, len(items))
	for _, item := range items {
		productIDs = append(productIDs, item.ID)
	}
	stats := h.svc.StatsForProducts(productIDs)

	type enrichedProduct struct {
		ID             string   `json:"id"`
		Name           string   `json:"name"`
		Vendor         string   `json:"vendor"`
		Category       string   `json:"category"`
		Description    string   `json:"description"`
		Homepage       string   `json:"homepage"`
		LogoURL        string   `json:"logo_url"`
		CPEPrefix      string   `json:"cpe_prefix"`
		Tags           []string `json:"tags"`
		Aliases        []string `json:"aliases"`
		CreatedAt      string   `json:"created_at"`
		UpdatedAt      string   `json:"updated_at"`
		PocCount       int64    `json:"poc_count"`
		FingerprintCnt int64    `json:"fingerprint_count"`
		VulnCount      int64    `json:"vuln_count"`
	}

	result := make([]enrichedProduct, 0, len(items))
	for _, item := range items {
		ep := enrichedProduct{
			ID:          item.ID,
			Name:        item.Name,
			Vendor:      item.Vendor,
			Category:    item.Category,
			Description: item.Description,
			Homepage:    item.Homepage,
			LogoURL:     item.LogoURL,
			CPEPrefix:   item.CPEPrefix,
			Tags:        item.Tags,
			Aliases:     item.Aliases,
			CreatedAt:   item.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   item.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if s, ok := stats[item.ID]; ok {
			ep.PocCount = s.PocCount
			ep.FingerprintCnt = s.FingerprintCnt
			ep.VulnCount = s.VulnCount
		}
		result = append(result, ep)
	}

	web.Succeed(c).List(count, result).Send()
}

func (h *HandlerProduct) GetByID(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	item, err := h.svc.GetByID(uri.Id)
	if err != nil {
		web.Err(c, web.NotFound).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *HandlerProduct) Create(c *gin.Context) {
	req, ok := web.BindJSON[ProductCreateReq](c)
	if !ok {
		return
	}
	user, _ := iamsdk.GetCurrentUser(c)
	item, err := h.svc.Create(req, user.UserID)
	if err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Data(item).Send()
}

func (h *HandlerProduct) Update(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	req, ok := web.BindJSON[ProductUpdateReq](c)
	if !ok {
		return
	}
	if err := h.svc.Update(uri.Id, req); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerProduct) Delete(c *gin.Context) {
	uri, ok := web.BindUri[web.Id](c)
	if !ok {
		return
	}
	if err := h.svc.Delete(uri.Id); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Send()
}

func (h *HandlerProduct) Backfill(c *gin.Context) {
	pocUpdated, fpUpdated := h.svc.BackfillExisting()
	web.Succeed(c).Data(gin.H{
		"poc_updated":         pocUpdated,
		"fingerprint_updated": fpUpdated,
	}).Send()
}

func (h *HandlerProduct) Search(c *gin.Context) {
	keyword := c.Query("keyword")
	if keyword == "" {
		web.Succeed(c).Data([]interface{}{}).Send()
		return
	}
	items, _, _ := h.svc.List(ProductQuery{Keyword: keyword, PageSize: 20, Page: 1})
	web.Succeed(c).Data(items).Send()
}

func (h *HandlerProduct) Summary(c *gin.Context) {
	vendors := h.svc.VendorSummary()
	categories := h.svc.CategorySummary()
	web.Succeed(c).Data(gin.H{
		"vendors":    vendors,
		"categories": categories,
	}).Send()
}

func (h *HandlerProduct) Reclassify(c *gin.Context) {
	updated := h.svc.ReclassifyAll()
	web.Succeed(c).Data(gin.H{"updated": updated}).Send()
}
