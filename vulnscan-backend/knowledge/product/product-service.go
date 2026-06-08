package product

import (
	"log/slog"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

type ProductQuery struct {
	Page     int    `form:"page"`
	PageSize int    `form:"page_size"`
	Keyword  string `form:"keyword"`
	Category string `form:"category"`
	Vendor   string `form:"vendor"`
}

type ProductCreateReq struct {
	Name        string   `json:"name" binding:"required"`
	Vendor      string   `json:"vendor"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Homepage    string   `json:"homepage"`
	LogoURL     string   `json:"logo_url"`
	CPEPrefix   string   `json:"cpe_prefix"`
	Tags        []string `json:"tags"`
	Aliases     []string `json:"aliases"`
}

type ProductUpdateReq struct {
	Name        *string  `json:"name"`
	Vendor      *string  `json:"vendor"`
	Category    *string  `json:"category"`
	Description *string  `json:"description"`
	Homepage    *string  `json:"homepage"`
	LogoURL     *string  `json:"logo_url"`
	CPEPrefix   *string  `json:"cpe_prefix"`
	Tags        []string `json:"tags"`
	Aliases     []string `json:"aliases"`
}

type ProductStats struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Vendor         string `json:"vendor"`
	Category       string `json:"category"`
	PocCount       int64  `json:"poc_count"`
	FingerprintCnt int64  `json:"fingerprint_count"`
	VulnCount      int64  `json:"vuln_count"`
}

type ServiceProduct struct {
	db *db.DB
}

func NewServiceProduct(database *db.DB) *ServiceProduct {
	return &ServiceProduct{db: database}
}

func (s *ServiceProduct) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *ServiceProduct) List(q ProductQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Product, int64, error) {
	tx := s.session().Model(&model.Product{}).Scopes(scopes...)
	if q.Keyword != "" {
		like := "%" + q.Keyword + "%"
		tx = tx.Where("name LIKE ? OR vendor LIKE ? OR description LIKE ? OR aliases LIKE ?", like, like, like, like)
	}
	if q.Category != "" {
		tx = tx.Where("category = ?", q.Category)
	}
	if q.Vendor != "" {
		tx = tx.Where("vendor = ?", q.Vendor)
	}

	var count int64
	tx.Count(&count)

	if q.PageSize <= 0 {
		q.PageSize = 20
	}
	if q.Page <= 0 {
		q.Page = 1
	}
	offset := (q.Page - 1) * q.PageSize

	var items []model.Product
	if err := tx.Offset(offset).Limit(q.PageSize).Order("name ASC").Find(&items).Error; err != nil {
		return nil, 0, err
	}
	return items, count, nil
}

func (s *ServiceProduct) GetByID(id string) (*model.Product, error) {
	var item model.Product
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceProduct) GetByName(name string) (*model.Product, error) {
	var item model.Product
	canonical := canonicalize(name)
	if err := s.session().Where("name = ?", canonical).First(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceProduct) Create(req ProductCreateReq, createdBy string) (*model.Product, error) {
	item := model.Product{
		Name:        canonicalize(req.Name),
		Vendor:      strings.TrimSpace(req.Vendor),
		Category:    strings.TrimSpace(req.Category),
		Description: req.Description,
		Homepage:    strings.TrimSpace(req.Homepage),
		LogoURL:     strings.TrimSpace(req.LogoURL),
		CPEPrefix:   strings.TrimSpace(req.CPEPrefix),
		Tags:        req.Tags,
		Aliases:     req.Aliases,
	}
	item.ID = ulid.GenerateID()
	item.CreatedBy = createdBy

	if err := s.session().Create(&item).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *ServiceProduct) Update(id string, req ProductUpdateReq) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = canonicalize(*req.Name)
	}
	if req.Vendor != nil {
		updates["vendor"] = strings.TrimSpace(*req.Vendor)
	}
	if req.Category != nil {
		updates["category"] = strings.TrimSpace(*req.Category)
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Homepage != nil {
		updates["homepage"] = strings.TrimSpace(*req.Homepage)
	}
	if req.LogoURL != nil {
		updates["logo_url"] = strings.TrimSpace(*req.LogoURL)
	}
	if req.CPEPrefix != nil {
		updates["cpe_prefix"] = strings.TrimSpace(*req.CPEPrefix)
	}
	if req.Tags != nil {
		updates["tags"] = model.StringArray(req.Tags)
	}
	if req.Aliases != nil {
		updates["aliases"] = model.StringArray(req.Aliases)
	}
	if len(updates) == 0 {
		return nil
	}
	return s.session().Model(&model.Product{}).Where("id = ?", id).Updates(updates).Error
}

func (s *ServiceProduct) Delete(id string) error {
	return s.session().Where("id = ?", id).Delete(&model.Product{}).Error
}

// MatchOrCreate finds or creates a product by name. This is the core auto-linking function.
func (s *ServiceProduct) MatchOrCreate(name, vendor string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	canonical := canonicalize(name)

	var existing model.Product
	err := s.session().Where("name = ?", canonical).First(&existing).Error
	if err == nil {
		if existing.Vendor == "" && vendor != "" {
			s.session().Model(&existing).Update("vendor", strings.TrimSpace(vendor))
		}
		return existing.ID
	}
	if err != gorm.ErrRecordNotFound {
		return ""
	}

	// Try alias match
	err = s.session().Where("aliases LIKE ?", "%\""+canonical+"\"%").First(&existing).Error
	if err == nil {
		return existing.ID
	}

	item := model.Product{
		Name:     canonical,
		Vendor:   strings.TrimSpace(vendor),
		Category: guessCategory(canonical),
	}
	item.ID = ulid.GenerateID()
	item.CreatedBy = "system"

	if err := s.session().Create(&item).Error; err != nil {
		slog.Debug("[ProductService] 自动创建产品失败", "name", canonical, "error", err)
		return ""
	}
	slog.Info("[ProductService] 自动创建产品", "name", canonical, "vendor", vendor, "id", item.ID)
	return item.ID
}

// StatsForProducts returns enriched stats for product list display.
func (s *ServiceProduct) StatsForProducts(productIDs []string) map[string]*ProductStats {
	result := make(map[string]*ProductStats, len(productIDs))
	if len(productIDs) == 0 {
		return result
	}

	type countRow struct {
		ProductID string `gorm:"column:product_id"`
		Cnt       int64  `gorm:"column:cnt"`
	}

	var pocCounts []countRow
	s.session().Model(&model.PocTemplate{}).
		Select("product_id, count(*) as cnt").
		Where("product_id IN ? AND product_id != ''", productIDs).
		Group("product_id").Find(&pocCounts)
	for _, r := range pocCounts {
		if _, ok := result[r.ProductID]; !ok {
			result[r.ProductID] = &ProductStats{ID: r.ProductID}
		}
		result[r.ProductID].PocCount = r.Cnt
	}

	var fpCounts []countRow
	s.session().Model(&model.WebFingerprint{}).
		Select("product_id, count(*) as cnt").
		Where("product_id IN ? AND product_id != ''", productIDs).
		Group("product_id").Find(&fpCounts)
	for _, r := range fpCounts {
		if _, ok := result[r.ProductID]; !ok {
			result[r.ProductID] = &ProductStats{ID: r.ProductID}
		}
		result[r.ProductID].FingerprintCnt = r.Cnt
	}

	var vulnCounts []countRow
	s.session().Model(&model.Vulnerability{}).
		Select("product_id, count(*) as cnt").
		Where("product_id IN ? AND product_id != ''", productIDs).
		Group("product_id").Find(&vulnCounts)
	for _, r := range vulnCounts {
		if _, ok := result[r.ProductID]; !ok {
			result[r.ProductID] = &ProductStats{ID: r.ProductID}
		}
		result[r.ProductID].VulnCount = r.Cnt
	}

	return result
}

// VendorSummary returns distinct vendors with product counts.
func (s *ServiceProduct) VendorSummary() []VendorGroup {
	type row struct {
		Vendor string `gorm:"column:vendor"`
		Cnt    int64  `gorm:"column:cnt"`
	}
	var rows []row
	s.session().Model(&model.Product{}).
		Select("vendor, count(*) as cnt").
		Where("vendor != ''").
		Group("vendor").
		Order("cnt DESC").
		Find(&rows)

	result := make([]VendorGroup, 0, len(rows))
	for _, r := range rows {
		result = append(result, VendorGroup{Vendor: r.Vendor, Count: r.Cnt})
	}
	return result
}

// CategorySummary returns distinct categories with product counts.
func (s *ServiceProduct) CategorySummary() []CategoryGroup {
	type row struct {
		Category string `gorm:"column:category"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	var rows []row
	s.session().Model(&model.Product{}).
		Select("category, count(*) as cnt").
		Group("category").
		Order("cnt DESC").
		Find(&rows)

	result := make([]CategoryGroup, 0, len(rows))
	for _, r := range rows {
		result = append(result, CategoryGroup{Category: r.Category, Count: r.Cnt})
	}
	return result
}

type VendorGroup struct {
	Vendor string `json:"vendor"`
	Count  int64  `json:"count"`
}

type CategoryGroup struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// ReclassifyAll re-runs guessCategory on all products with category "other" or empty.
func (s *ServiceProduct) ReclassifyAll() int {
	var products []model.Product
	s.session().Where("category = '' OR category = 'other'").Find(&products)
	updated := 0
	for _, p := range products {
		cat := guessCategory(p.Name)
		if cat != "other" && cat != p.Category {
			s.session().Model(&model.Product{}).Where("id = ?", p.ID).Update("category", cat)
			updated++
		}
	}
	return updated
}

// BackfillExisting scans all PoC and fingerprint records without ProductID and auto-links them.
func (s *ServiceProduct) BackfillExisting() (int, int) {
	var pocUpdated, fpUpdated int

	var pocs []model.PocTemplate
	s.session().Where("product != '' AND (product_id = '' OR product_id IS NULL)").
		Select("id, product, vendor").Limit(5000).Find(&pocs)
	for _, p := range pocs {
		pid := s.MatchOrCreate(p.Product, p.Vendor)
		if pid != "" {
			s.session().Model(&model.PocTemplate{}).Where("id = ?", p.ID).Update("product_id", pid)
			pocUpdated++
		}
	}

	var fps []model.WebFingerprint
	s.session().Where("product != '' AND (product_id = '' OR product_id IS NULL)").
		Select("id, product").Limit(5000).Find(&fps)
	for _, fp := range fps {
		pid := s.MatchOrCreate(fp.Product, "")
		if pid != "" {
			s.session().Model(&model.WebFingerprint{}).Where("id = ?", fp.ID).Update("product_id", pid)
			fpUpdated++
		}
	}

	if pocUpdated > 0 || fpUpdated > 0 {
		slog.Info("[ProductService] 回填完成", "poc_updated", pocUpdated, "fp_updated", fpUpdated)
	}
	return pocUpdated, fpUpdated
}

func canonicalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func guessCategory(name string) string {
	lower := strings.ToLower(name)
	categoryMap := map[string][]string{
		"web-server":   {"nginx", "apache", "httpd", "iis", "lighttpd", "caddy", "traefik", "haproxy", "openresty", "tengine", "litespeed", "envoy", "tomcat", "jetty", "undertow", "weblogic", "websphere", "glassfish", "wildfly", "gunicorn", "uvicorn", "kestrel", "cowboy", "puma", "unicorn"},
		"cms":          {"wordpress", "drupal", "joomla", "typo3", "ghost", "strapi", "concrete5", "moodle", "xoops", "plone", "umbraco", "kentico", "sitecore", "contentful", "magento", "shopify", "prestashop", "opencart", "woocommerce", "mediawiki", "dokuwiki", "confluence", "xwiki", "discuz", "phpbb", "mybb", "vbulletin"},
		"framework":    {"spring", "django", "flask", "laravel", "express", "rails", "fastapi", "gin", "fiber", "echo", "koa", "nest", "hapi", "aiohttp", "tornado", "sanic", "starlette", "pyramid", "bottle", "cherrypy", "falcon", "symfony", "codeigniter", "cakephp", "yii", "zend", "slim", "lumen", "thinkphp", "beego", "iris", "revel", "play", "grails", "struts", "vaadin", "wicket", "tapestry", "jsf"},
		"database":     {"mysql", "mariadb", "postgres", "redis", "mongodb", "elasticsearch", "mssql", "oracle", "sqlite", "couchdb", "cassandra", "clickhouse", "influxdb", "neo4j", "cockroach", "tidb", "memcached", "etcd", "couchbase", "dynamodb", "firebird", "db2", "sybase", "hbase", "aerospike"},
		"language":     {"php", "python", "java", "node", "ruby", "perl", "dotnet", ".net_framework", "asp.net"},
		"js-framework": {"react", "vue", "angular", "next", "nuxt", "svelte", "gatsby", "remix", "solid", "ember", "backbone", "meteor"},
		"js-library":   {"jquery", "lodash", "bootstrap", "axios", "moment", "chart.js", "d3", "three.js", "leaflet", "swiper"},
		"ci-cd":        {"jenkins", "gitlab", "bamboo", "teamcity", "drone", "argo", "circleci", "travis", "concourse", "gocd", "buildbot", "hudson"},
		"container":    {"docker", "kubernetes", "k8s", "rancher", "portainer", "helm", "istio", "podman", "containerd", "nomad", "mesos", "marathon", "swarm"},
		"monitor":      {"grafana", "prometheus", "zabbix", "nagios", "datadog", "kibana", "graylog", "logstash", "fluentd", "sentry", "newrelic", "dynatrace", "icinga", "cacti", "munin", "netdata", "telegraf", "victoria_metrics"},
		"microservice": {"nacos", "consul", "eureka", "apollo", "dubbo", "sentinel", "seata", "skywalking", "zipkin", "jaeger", "kong", "apisix", "zuul", "gateway", "ribbon", "feign", "hystrix"},
		"mail":         {"exchange", "postfix", "sendmail", "zimbra", "roundcube", "thunderbird", "dovecot", "hmailserver", "mailu", "mailcow", "iredmail"},
		"vpn":          {"openvpn", "wireguard", "fortivpn", "pulse_secure", "sonicwall_vpn", "globalprotect", "anyconnect", "ipsec", "strongswan"},
		"firewall":     {"pfsense", "fortinet", "fortigate", "sophos", "checkpoint", "paloalto", "modsecurity", "waf", "imperva", "f5_big", "barracuda", "cloudflare"},
		"oa":           {"oa", "泛微", "用友", "致远", "通达", "蓝凌", "金蝶", "万户"},
		"network":      {"cisco", "huawei", "juniper", "mikrotik", "ubiquiti", "netgear", "tp-link", "tplink", "zyxel", "dlink", "d-link", "aruba", "ruckus", "meraki"},
		"storage":      {"minio", "ceph", "gluster", "nexus", "harbor", "artifactory", "registry", "s3", "oss"},
		"queue":        {"rabbitmq", "kafka", "rocketmq", "activemq", "nats", "nsq", "pulsar", "zeromq", "beanstalkd"},
		"scada":        {"modbus", "bacnet", "s7comm", "dnp3", "opc", "plc", "scada", "hmi", "siemens"},
	}
	for cat, keywords := range categoryMap {
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				return cat
			}
		}
	}
	if strings.HasSuffix(lower, "_plugin") || strings.HasSuffix(lower, "-plugin") ||
		strings.HasSuffix(lower, "_theme") || strings.HasSuffix(lower, "-theme") ||
		strings.HasSuffix(lower, "_addon") || strings.HasSuffix(lower, "-addon") {
		return "plugin"
	}
	return "other"
}
