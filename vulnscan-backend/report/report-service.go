package report

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type ServiceReport struct {
	db *db.DB
}

func NewServiceReport(database *db.DB) *ServiceReport {
	return &ServiceReport{db: database}
}

func (s *ServiceReport) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// AvailableTasks returns completed scan tasks for report generation.
func (s *ServiceReport) AvailableTasks() []model.ScanTask {
	var tasks []model.ScanTask
	s.session().Where("status = ?", "completed").
		Order("finished_at DESC").
		Limit(50).
		Select("id, name, targets, status, finished_at, created_at, total_targets").
		Find(&tasks)
	return tasks
}

// GetTask retrieves a single scan task by ID.
func (s *ServiceReport) GetTask(taskID string) (*model.ScanTask, error) {
	var task model.ScanTask
	if err := s.session().First(&task, "id = ?", taskID).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

// BuildReportData assembles task-level report data from vulnerabilities and findings.
func (s *ServiceReport) BuildReportData(title, reportType, taskID string) *ReportData {
	data := &ReportData{
		Title:             title,
		GeneratedAt:       time.Now(),
		GeneratedBy:       "system",
		Vulnerabilities:   []VulnItem{},
		DiscoveryFindings: []DiscoveryItem{},
		DiscoveryGroups:   []DiscoveryGroup{},
		Assets:            []AssetItem{},
	}

	if taskID != "" {
		if task, err := s.GetTask(taskID); err == nil {
			data.Task = &ReportTaskMeta{
				ID:         task.ID,
				Name:       task.Name,
				Status:     task.Status,
				Targets:    task.Targets,
				StartedAt:  task.StartedAt,
				FinishedAt: task.FinishedAt,
			}
			if data.Title == "" {
				data.Title = fmt.Sprintf("扫描任务报告 - %s", task.Name)
			}
		}

		s.populateTaskReport(data, taskID)
	} else {
		s.populateGlobalVulns(data)
	}

	data.Summary = buildReportSummary(data)
	if data.Task != nil {
		data.Summary.ScanDuration = formatScanDuration(data.Task.StartedAt, data.Task.FinishedAt)
	}

	if reportType == TypeASM {
		data.Title += " (ASM)"
	}
	if data.Title == "" {
		data.Title = "扫描报告"
	}

	s.enrichProducts(data)

	return data
}

func (s *ServiceReport) populateTaskReport(data *ReportData, taskID string) {
	var findings []model.ScanFinding
	s.session().
		Where("task_id = ?", taskID).
		Order("created_at DESC").
		Limit(2000).
		Find(&findings)

	if len(findings) == 0 {
		s.populateFallbackTaskVulns(data, taskID)
		return
	}

	assetMap := map[string]*AssetItem{}
	discoveryGroupMap := map[string]*DiscoveryGroup{}

	for _, finding := range findings {
		asset := ensureAssetItem(assetMap, finding.Target)
		enrichAssetItem(asset, finding)
		asset.FindingCount++

		if model.NormalizeFindingCategory(finding.Category, finding.ModuleID, finding.Type) == model.FindingCategoryVuln {
			data.Vulnerabilities = append(data.Vulnerabilities, findingToVulnItem(finding))
			asset.VulnCount++
			continue
		}

		data.DiscoveryFindings = append(data.DiscoveryFindings, findingToDiscoveryItem(finding))
		group := ensureDiscoveryGroup(discoveryGroupMap, finding.Type)
		group.Count++
	}

	data.Assets = sortAssetItems(assetMap)
	data.DiscoveryGroups = sortDiscoveryGroups(discoveryGroupMap)
	sortVulnerabilities(data.Vulnerabilities)
	sortDiscoveryFindings(data.DiscoveryFindings)
}

func (s *ServiceReport) populateFallbackTaskVulns(data *ReportData, taskID string) {
	var vulns []model.Vulnerability
	s.session().
		Where("task_id = ?", taskID).
		Order("severity DESC, created_at DESC").
		Limit(1000).
		Find(&vulns)

	assetMap := map[string]*AssetItem{}
	for _, vuln := range vulns {
		data.Vulnerabilities = append(data.Vulnerabilities, vulnerabilityToVulnItem(vuln))
		asset := ensureAssetItem(assetMap, vuln.Target)
		if vuln.Port > 0 {
			asset.OpenPorts = appendUniqueInt(asset.OpenPorts, vuln.Port)
		}
		asset.Services = appendUniqueString(asset.Services, vuln.Protocol)
		asset.VulnCount++
		asset.FindingCount++
	}

	data.Assets = sortAssetItems(assetMap)
	sortVulnerabilities(data.Vulnerabilities)
}

func (s *ServiceReport) populateGlobalVulns(data *ReportData) {
	var vulns []model.Vulnerability
	s.session().
		Order("severity DESC, created_at DESC").
		Limit(1000).
		Find(&vulns)

	assetMap := map[string]*AssetItem{}
	for _, vuln := range vulns {
		data.Vulnerabilities = append(data.Vulnerabilities, vulnerabilityToVulnItem(vuln))
		asset := ensureAssetItem(assetMap, vuln.Target)
		if vuln.Port > 0 {
			asset.OpenPorts = appendUniqueInt(asset.OpenPorts, vuln.Port)
		}
		asset.Services = appendUniqueString(asset.Services, vuln.Protocol)
		asset.VulnCount++
		asset.FindingCount++
	}

	data.Assets = sortAssetItems(assetMap)
	sortVulnerabilities(data.Vulnerabilities)
}

func (s *ServiceReport) enrichProducts(data *ReportData) {
	// Collect ProductIDs from vulnerabilities
	productIDSet := make(map[string]struct{})
	if taskID := ""; data.Task != nil {
		taskID = data.Task.ID
		var vulns []model.Vulnerability
		s.session().Where("task_id = ? AND product_id != '' AND product_id IS NOT NULL", taskID).
			Select("product_id").Find(&vulns)
		for _, v := range vulns {
			if v.ProductID != "" {
				productIDSet[v.ProductID] = struct{}{}
			}
		}
	}

	if len(productIDSet) == 0 {
		return
	}

	productIDs := make([]string, 0, len(productIDSet))
	for pid := range productIDSet {
		productIDs = append(productIDs, pid)
	}

	var products []model.Product
	s.session().Where("id IN ?", productIDs).Find(&products)

	productMap := make(map[string]*model.Product, len(products))
	for i := range products {
		productMap[products[i].ID] = &products[i]
	}

	// Count vulns per product
	vulnCountMap := make(map[string]int)
	if data.Task != nil {
		type cntRow struct {
			ProductID string `gorm:"column:product_id"`
			Cnt       int    `gorm:"column:cnt"`
		}
		var counts []cntRow
		s.session().Model(&model.Vulnerability{}).
			Select("product_id, count(*) as cnt").
			Where("task_id = ? AND product_id IN ?", data.Task.ID, productIDs).
			Group("product_id").Find(&counts)
		for _, r := range counts {
			vulnCountMap[r.ProductID] = r.Cnt
		}
	}

	// Count PoCs per product
	pocCountMap := make(map[string]int)
	{
		type cntRow struct {
			ProductID string `gorm:"column:product_id"`
			Cnt       int    `gorm:"column:cnt"`
		}
		var counts []cntRow
		s.session().Model(&model.PocTemplate{}).
			Select("product_id, count(*) as cnt").
			Where("product_id IN ?", productIDs).
			Group("product_id").Find(&counts)
		for _, r := range counts {
			pocCountMap[r.ProductID] = r.Cnt
		}
	}

	for _, pid := range productIDs {
		p, ok := productMap[pid]
		if !ok {
			continue
		}
		data.Products = append(data.Products, ProductSection{
			ID:          p.ID,
			Name:        p.Name,
			Vendor:      p.Vendor,
			Category:    p.Category,
			Description: p.Description,
			Homepage:    p.Homepage,
			VulnCount:   vulnCountMap[pid],
			PocCount:    pocCountMap[pid],
		})
	}

	// Enrich VulnItem with product names
	for i := range data.Vulnerabilities {
		vi := &data.Vulnerabilities[i]
		if vi.ProductID == "" {
			continue
		}
		if p, ok := productMap[vi.ProductID]; ok {
			vi.ProductName = p.Name
		}
	}
}

func buildReportSummary(data *ReportData) ReportSummary {
	var criticalCount, highCount, mediumCount, lowCount, infoCount int
	for _, vuln := range data.Vulnerabilities {
		switch normalizeSeverity(vuln.Severity) {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	totalAssets := len(data.Assets)
	if totalAssets == 0 && data.Task != nil {
		totalAssets = len(data.Task.Targets)
	}

	return ReportSummary{
		TotalAssets:        totalAssets,
		TotalFindings:      len(data.Vulnerabilities) + len(data.DiscoveryFindings),
		TotalVulns:         len(data.Vulnerabilities),
		DiscoveryCount:     len(data.DiscoveryFindings),
		TotalDiscoveryType: len(data.DiscoveryGroups),
		CriticalCount:      criticalCount,
		HighCount:          highCount,
		MediumCount:        mediumCount,
		LowCount:           lowCount,
		InfoCount:          infoCount,
		RiskScore: calculateRiskScore(
			criticalCount,
			highCount,
			mediumCount,
			lowCount,
			infoCount,
			len(data.DiscoveryFindings),
			totalAssets,
		),
	}
}

func findingToVulnItem(f model.ScanFinding) VulnItem {
	return VulnItem{
		ID:          f.ID,
		Title:       firstNonEmpty(f.Title, humanizeFindingType(f.Type)),
		Severity:    normalizeSeverity(f.Severity),
		CVEID:       extractString(f.Data, "cve_id", "cve"),
		Asset:       formatTargetWithPort(f.Target, f.Port),
		Status:      model.VulnStatusOpen,
		Description: f.Description,
		Evidence:    f.Evidence,
		Remediation: extractString(f.Data, "remediation", "solution", "fix"),
	}
}

func vulnerabilityToVulnItem(v model.Vulnerability) VulnItem {
	cveID := ""
	if len(v.CVEIDs) > 0 {
		cveID = v.CVEIDs[0]
	}
	return VulnItem{
		ID:          v.ID,
		Title:       v.Title,
		Severity:    normalizeSeverity(v.Severity),
		CVEID:       cveID,
		Asset:       formatTargetWithPort(v.Target, v.Port),
		Status:      v.Status,
		Description: v.Description,
		Evidence:    v.Evidence,
		Remediation: v.Solution,
		ProductID:   v.ProductID,
	}
}

func findingToDiscoveryItem(f model.ScanFinding) DiscoveryItem {
	return DiscoveryItem{
		ID:          f.ID,
		Category:    f.Category,
		Type:        f.Type,
		TypeLabel:   humanizeFindingType(f.Type),
		Title:       firstNonEmpty(f.Title, humanizeFindingType(f.Type)),
		Target:      f.Target,
		Port:        f.Port,
		Protocol:    f.Protocol,
		Severity:    normalizeSeverity(f.Severity),
		Confidence:  f.Confidence,
		ModuleID:    f.ModuleID,
		Description: f.Description,
		Evidence:    f.Evidence,
		Summary:     summarizeFinding(f),
		CreatedAt:   f.CreatedAt,
	}
}

func ensureAssetItem(assetMap map[string]*AssetItem, target string) *AssetItem {
	key := strings.TrimSpace(target)
	if key == "" {
		key = "unknown"
	}
	if assetMap[key] == nil {
		assetMap[key] = &AssetItem{Host: key}
	}
	return assetMap[key]
}

func enrichAssetItem(item *AssetItem, finding model.ScanFinding) {
	if item == nil {
		return
	}
	if finding.Port > 0 {
		item.OpenPorts = appendUniqueInt(item.OpenPorts, finding.Port)
	}
	item.Services = appendUniqueString(
		item.Services,
		extractString(finding.Data, "service", "server", "protocol"),
	)
	item.Fingerprints = appendUniqueString(
		item.Fingerprints,
		extractString(finding.Data, "tech", "technology", "waf", "favicon_hash", "jarm_hash"),
	)
	if item.IP == "" {
		item.IP = extractString(finding.Data, "ip", "site_ip", "real_ip")
	}
}

func ensureDiscoveryGroup(groupMap map[string]*DiscoveryGroup, findingType string) *DiscoveryGroup {
	key := strings.TrimSpace(findingType)
	if key == "" {
		key = "unknown"
	}
	if groupMap[key] == nil {
		groupMap[key] = &DiscoveryGroup{
			Type:  key,
			Label: humanizeFindingType(key),
		}
	}
	return groupMap[key]
}

func sortAssetItems(assetMap map[string]*AssetItem) []AssetItem {
	items := make([]AssetItem, 0, len(assetMap))
	for _, item := range assetMap {
		item.OpenPorts = sortedInts(item.OpenPorts)
		item.Services = sortedStrings(item.Services)
		item.Fingerprints = sortedStrings(item.Fingerprints)
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].VulnCount != items[j].VulnCount {
			return items[i].VulnCount > items[j].VulnCount
		}
		if items[i].FindingCount != items[j].FindingCount {
			return items[i].FindingCount > items[j].FindingCount
		}
		return items[i].Host < items[j].Host
	})
	return items
}

func sortDiscoveryGroups(groupMap map[string]*DiscoveryGroup) []DiscoveryGroup {
	groups := make([]DiscoveryGroup, 0, len(groupMap))
	for _, group := range groupMap {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].Label < groups[j].Label
	})
	return groups
}

func sortVulnerabilities(items []VulnItem) {
	sort.Slice(items, func(i, j int) bool {
		leftRank := severityRank(items[i].Severity)
		rightRank := severityRank(items[j].Severity)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if items[i].Asset != items[j].Asset {
			return items[i].Asset < items[j].Asset
		}
		return items[i].Title < items[j].Title
	})
}

func sortDiscoveryFindings(items []DiscoveryItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			if items[i].TypeLabel != items[j].TypeLabel {
				return items[i].TypeLabel < items[j].TypeLabel
			}
			return items[i].Target < items[j].Target
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
}

func calculateRiskScore(criticalCount, highCount, mediumCount, lowCount, infoCount, discoveryCount, totalAssets int) float64 {
	weighted := criticalCount*25 + highCount*12 + mediumCount*6 + lowCount*2 + infoCount
	if totalAssets > 0 {
		weighted += int(math.Ceil(float64(discoveryCount) / float64(totalAssets)))
	} else {
		weighted += discoveryCount / 3
	}
	score := math.Min(100, float64(weighted))
	return math.Round(score*100) / 100
}

func formatScanDuration(startedAt, finishedAt *time.Time) string {
	if startedAt == nil {
		return ""
	}
	end := time.Now()
	if finishedAt != nil {
		end = *finishedAt
	}
	if end.Before(*startedAt) {
		return ""
	}
	duration := end.Sub(*startedAt)
	if duration < time.Minute {
		return fmt.Sprintf("%d秒", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%d分%d秒", int(duration.Minutes()), int(duration.Seconds())%60)
	}
	return fmt.Sprintf("%d小时%d分", int(duration.Hours()), int(duration.Minutes())%60)
}

func summarizeFinding(f model.ScanFinding) string {
	parts := make([]string, 0, 6)
	parts = appendIfMissing(parts, formatTargetWithPort(f.Target, f.Port))
	parts = appendIfMissing(parts, extractString(f.Data, "url"))
	if service := strings.TrimSpace(strings.Join([]string{
		extractString(f.Data, "service"),
		extractString(f.Data, "version"),
	}, " ")); service != "" {
		parts = appendIfMissing(parts, service)
	}
	parts = appendIfMissing(parts, extractString(f.Data, "ip", "real_ip"))
	parts = appendIfMissing(parts, extractString(f.Data, "title", "name", "value"))
	if len(parts) == 0 {
		parts = appendIfMissing(parts, strings.TrimSpace(f.Description))
	}
	return strings.Join(parts, " | ")
}

func appendIfMissing(parts []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return parts
	}
	for _, part := range parts {
		if part == value {
			return parts
		}
	}
	return append(parts, value)
}

func appendUniqueString(values []string, candidates ...string) []string {
	exists := make(map[string]struct{}, len(values))
	for _, value := range values {
		exists[value] = struct{}{}
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := exists[candidate]; ok {
			continue
		}
		values = append(values, candidate)
		exists[candidate] = struct{}{}
	}
	return values
}

func appendUniqueInt(values []int, candidate int) []int {
	if candidate <= 0 {
		return values
	}
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}

func extractString(data model.JSONMap, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				return trimmed
			}
		case []string:
			if len(typed) > 0 {
				return strings.Join(typed, ", ")
			}
		case []interface{}:
			items := make([]string, 0, len(typed))
			for _, item := range typed {
				if item == nil {
					continue
				}
				text := strings.TrimSpace(fmt.Sprint(item))
				if text != "" {
					items = append(items, text)
				}
			}
			if len(items) > 0 {
				return strings.Join(items, ", ")
			}
		default:
			text := strings.TrimSpace(fmt.Sprint(typed))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func severityRank(severity string) int {
	switch normalizeSeverity(severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func normalizeSeverity(severity string) string {
	severity = strings.ToLower(strings.TrimSpace(severity))
	switch severity {
	case "critical", "high", "medium", "low", "info":
		return severity
	default:
		return "info"
	}
}

func formatTargetWithPort(target string, port int) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if port > 0 && !strings.Contains(target, ":"+strconv.Itoa(port)) {
		return fmt.Sprintf("%s:%d", target, port)
	}
	return target
}

func humanizeFindingType(findingType string) string {
	findingType = strings.TrimSpace(findingType)
	if findingType == "" {
		return "未分类发现"
	}
	parts := strings.Split(findingType, "_")
	for index, part := range parts {
		if part == "" {
			continue
		}
		parts[index] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func sortedInts(values []int) []int {
	cloned := append([]int(nil), values...)
	sort.Ints(cloned)
	return cloned
}

func sortedStrings(values []string) []string {
	cloned := append([]string(nil), values...)
	sort.Strings(cloned)
	return cloned
}

// CompareTasks compares vulnerabilities between two scan tasks.
func (s *ServiceReport) CompareTasks(baseTaskID, compareTaskID string) (*CompareResult, error) {
	return CompareTasks(s.session(), baseTaskID, compareTaskID)
}
