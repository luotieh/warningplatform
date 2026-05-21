package payload

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type Loader struct {
	db     *gorm.DB
	mu     sync.RWMutex
	loaded bool

	payloadsByCategory map[string][]model.VulnPayload
	patternsByCategory map[string][]model.VulnPayloadPattern
	configsByCategory  map[string]map[string]string
}

func NewLoader(db *gorm.DB) *Loader {
	return &Loader{
		db:                 db,
		payloadsByCategory: make(map[string][]model.VulnPayload),
		patternsByCategory: make(map[string][]model.VulnPayloadPattern),
		configsByCategory:  make(map[string]map[string]string),
	}
}

func (l *Loader) LoadAll() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.db == nil {
		slog.Warn("[Payload-Loader] 数据库未初始化，使用空加载器")
		l.loaded = true
		return nil
	}

	type entryWithCategory struct {
		model.DataLibraryEntry
		Category string
	}

	var payloadEntries []entryWithCategory
	if err := l.db.Table("vs_data_library_entry e").
		Select("e.*, lib.category").
		Joins("JOIN vs_data_library lib ON e.library_id = lib.id").
		Where("lib.type = ? AND lib.status = ? AND e.enabled = ?", model.DataLibTypePayload, model.DataLibStatusActive, true).
		Order("e.priority ASC").
		Find(&payloadEntries).Error; err != nil {
		return err
	}

	payloadsByCategory := make(map[string][]model.VulnPayload)
	for _, e := range payloadEntries {
		p := entryToPayload(e.DataLibraryEntry, e.Category)
		payloadsByCategory[e.Category] = append(payloadsByCategory[e.Category], p)
	}

	var patternEntries []entryWithCategory
	if err := l.db.Table("vs_data_library_entry e").
		Select("e.*, lib.category").
		Joins("JOIN vs_data_library lib ON e.library_id = lib.id").
		Where("lib.type = ? AND lib.status = ? AND e.enabled = ?", model.DataLibTypePattern, model.DataLibStatusActive, true).
		Find(&patternEntries).Error; err != nil {
		return err
	}

	patternsByCategory := make(map[string][]model.VulnPayloadPattern)
	for _, e := range patternEntries {
		p := entryToPattern(e.DataLibraryEntry, e.Category)
		patternsByCategory[e.Category] = append(patternsByCategory[e.Category], p)
	}

	var configEntries []entryWithCategory
	if err := l.db.Table("vs_data_library_entry e").
		Select("e.*, lib.category").
		Joins("JOIN vs_data_library lib ON e.library_id = lib.id").
		Where("lib.type = ? AND lib.status = ? AND e.enabled = ?", model.DataLibTypeConfig, model.DataLibStatusActive, true).
		Find(&configEntries).Error; err != nil {
		return err
	}

	configsByCategory := make(map[string]map[string]string)
	for _, e := range configEntries {
		configKey := getMetaString(e.Metadata, "config_key")
		if configKey == "" {
			continue
		}
		if _, ok := configsByCategory[e.Category]; !ok {
			configsByCategory[e.Category] = make(map[string]string)
		}
		configsByCategory[e.Category][configKey] = e.Value
	}

	l.payloadsByCategory = payloadsByCategory
	l.patternsByCategory = patternsByCategory
	l.configsByCategory = configsByCategory
	l.loaded = true

	slog.Info("[Payload-Loader] payload 加载完成",
		"categories", len(payloadsByCategory),
		"payloads", len(payloadEntries),
		"patterns", len(patternEntries),
		"configs", len(configEntries),
	)

	return nil
}

func entryToPayload(e model.DataLibraryEntry, category string) model.VulnPayload {
	return model.VulnPayload{
		Category:    category,
		Name:        e.Name,
		Value:       e.Value,
		Type:        e.Type,
		Databases:   getMetaString(e.Metadata, "databases"),
		Expect:      getMetaString(e.Metadata, "expect"),
		Context:     getMetaString(e.Metadata, "context"),
		Tags:        e.Tags,
		Severity:    getMetaString(e.Metadata, "severity"),
		Description: getMetaString(e.Metadata, "description"),
		Enabled:     e.Enabled,
		SortOrder:   e.Priority,
	}
}

func entryToPattern(e model.DataLibraryEntry, category string) model.VulnPayloadPattern {
	return model.VulnPayloadPattern{
		Category:    category,
		Name:        e.Name,
		Pattern:     e.Value,
		Description: getMetaString(e.Metadata, "description"),
		Severity:    getMetaString(e.Metadata, "severity"),
		Enabled:     e.Enabled,
	}
}

func getMetaString(meta model.JSONMap, key string) string {
	if meta == nil {
		return ""
	}
	if v, ok := meta[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (l *Loader) Reload() error {
	return l.LoadAll()
}

// VulnPayloadCategories 漏洞检测模块依赖的数据文库 category。
var VulnPayloadCategories = []string{
	"sqli", "xss", "ssrf", "cmdi", "lfi", "ssti", "xxe", "nosqli",
}

// CategoriesMissingPayloads 返回文库中无 payload 条目的 category。
func (l *Loader) CategoriesMissingPayloads() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var missing []string
	for _, cat := range VulnPayloadCategories {
		if len(l.payloadsByCategory[cat]) == 0 {
			missing = append(missing, cat)
		}
	}
	return missing
}

func (l *Loader) GetPayloads(category string) []model.VulnPayload {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if ps, ok := l.payloadsByCategory[category]; ok {
		return ps
	}
	return nil
}

func (l *Loader) GetPatterns(category string) []model.VulnPayloadPattern {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if ps, ok := l.patternsByCategory[category]; ok {
		return ps
	}
	return nil
}

func (l *Loader) GetConfig(category, key string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if cats, ok := l.configsByCategory[category]; ok {
		return cats[key]
	}
	return ""
}

func (l *Loader) GetConfigJSON(category, key string, v interface{}) error {
	val := l.GetConfig(category, key)
	if val == "" {
		return nil
	}
	return json.Unmarshal([]byte(val), v)
}

func (l *Loader) GetSQLi() *SQLiPayloadSet {
	payloads := l.GetPayloads("sqli")
	if len(payloads) == 0 {
		return nil
	}

	set := &SQLiPayloadSet{}
	for _, p := range payloads {
		switch p.Type {
		case "error":
			set.ErrorPayloads = append(set.ErrorPayloads, PayloadEntry{
				Value:     p.Value,
				Databases: splitStrings(p.Databases),
				Tags:      splitStrings(p.Tags),
			})
		case "time":
			set.TimePayloads = append(set.TimePayloads, PayloadEntry{
				Value:     p.Value,
				Databases: splitStrings(p.Databases),
				Tags:      splitStrings(p.Tags),
			})
		case "union":
			set.UnionPayloads = append(set.UnionPayloads, PayloadEntry{
				Value:     p.Value,
				Databases: splitStrings(p.Databases),
				Tags:      splitStrings(p.Tags),
			})
		case "boolean":
			set.BooleanPayloads = append(set.BooleanPayloads, PayloadEntry{
				Value:     p.Value,
				Databases: splitStrings(p.Databases),
				Tags:      splitStrings(p.Tags),
			})
		}
	}

	truePayload := l.GetConfig("sqli_boolean", "true_payload")
	falsePayload := l.GetConfig("sqli_boolean", "false_payload")
	if truePayload != "" && falsePayload != "" {
		set.BooleanPairs = []BooleanPair{
			{TruePayload: truePayload, FalsePayload: falsePayload},
		}
	}

	set.ErrorPatterns = l.GetPatterns("sqli_error")

	return set
}

func (l *Loader) GetXSS() *XSSPayloadSet {
	payloads := l.GetPayloads("xss")
	if len(payloads) == 0 {
		return nil
	}

	set := &XSSPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, XSSPayloadEntry{
			Value:   p.Value,
			Expect:  p.Expect,
			Context: p.Context,
			Tags:    splitStrings(p.Tags),
		})
	}

	set.DOMSinks = l.GetPatterns("dom_sink")
	set.DOMSources = l.GetPatterns("dom_source")

	return set
}

func (l *Loader) GetCRLF() *CRLFPayloadSet {
	payloads := l.GetPayloads("crlf")
	if len(payloads) == 0 {
		return nil
	}

	set := &CRLFPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
		set.Params = append(set.Params, extractCRLFParam(p.Value))
	}
	return set
}

func (l *Loader) GetHostHeader() *HostHeaderPayloadSet {
	payloads := l.GetPayloads("host_header")
	if len(payloads) == 0 {
		return nil
	}

	set := &HostHeaderPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetSSRF() *SSRFPayloadSet {
	payloads := l.GetPayloads("ssrf")
	if len(payloads) == 0 {
		return nil
	}

	set := &SSRFPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetCmdi() *CmdiPayloadSet {
	payloads := l.GetPayloads("cmdi")
	if len(payloads) == 0 {
		return nil
	}

	set := &CmdiPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value:     p.Value,
			Databases: splitStrings(p.Databases),
			Tags:      splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetLFI() *LFIPayloadSet {
	payloads := l.GetPayloads("lfi")
	if len(payloads) == 0 {
		return nil
	}

	set := &LFIPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value:     p.Value,
			Databases: splitStrings(p.Databases),
			Tags:      splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetSSTI() *SSTIPayloadSet {
	payloads := l.GetPayloads("ssti")
	if len(payloads) == 0 {
		return nil
	}

	set := &SSTIPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetXXE() *XXEPayloadSet {
	payloads := l.GetPayloads("xxe")
	if len(payloads) == 0 {
		return nil
	}

	set := &XXEPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetNoSQLi() *NoSQLiPayloadSet {
	payloads := l.GetPayloads("nosqli")
	if len(payloads) == 0 {
		return nil
	}

	set := &NoSQLiPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetSensitiveData() *SensitiveDataPayloadSet {
	patterns := l.GetPatterns("sensitive_data")
	if len(patterns) == 0 {
		return nil
	}

	set := &SensitiveDataPayloadSet{}
	for _, p := range patterns {
		set.Patterns = append(set.Patterns, PatternEntry{
			Pattern:     p.Pattern,
			Name:        p.Name,
			Description: p.Description,
			Severity:    p.Severity,
		})
	}
	return set
}

func (l *Loader) GetSessionFixation() *SessionFixationPayloadSet {
	var paths []string
	if err := l.GetConfigJSON("session_fix_paths", "login_paths", &paths); err != nil {
		return nil
	}
	if len(paths) == 0 {
		return nil
	}

	return &SessionFixationPayloadSet{Paths: paths}
}

func (l *Loader) GetHTTPSmuggling() *HTTPSmugglingPayloadSet {
	payloads := l.GetPayloads("http_smuggling")
	if len(payloads) == 0 {
		return nil
	}

	set := &HTTPSmugglingPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}

	clte := l.GetConfig("http_smuggling", "cl_te_body")
	tecl := l.GetConfig("http_smuggling", "te_cl_body")
	if clte != "" {
		set.CLTEBody = clte
	}
	if tecl != "" {
		set.TECLBody = tecl
	}

	return set
}

func (l *Loader) GetXMLRPC() *XMLRPCPayloadSet {
	payloads := l.GetPayloads("xmlrpc")
	if len(payloads) == 0 {
		return nil
	}

	set := &XMLRPCPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetDirTraversal() *DirTraversalPayloadSet {
	payloads := l.GetPayloads("dir_traversal")
	if len(payloads) == 0 {
		return nil
	}

	set := &DirTraversalPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value:     p.Value,
			Databases: splitStrings(p.Databases),
			Tags:      splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetOpenRedirect() *OpenRedirectPayloadSet {
	payloads := l.GetPayloads("open_redirect")
	if len(payloads) == 0 {
		return nil
	}

	set := &OpenRedirectPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetFileUpload() *FileUploadPayloadSet {
	payloads := l.GetPayloads("file_upload")
	if len(payloads) == 0 {
		return nil
	}

	set := &FileUploadPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetDeserialization() *DeserializationPayloadSet {
	payloads := l.GetPayloads("deserialization")
	if len(payloads) == 0 {
		return nil
	}

	set := &DeserializationPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetAuthBypass() *AuthBypassPayloadSet {
	payloads := l.GetPayloads("auth_bypass")
	if len(payloads) == 0 {
		return nil
	}

	set := &AuthBypassPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value:     p.Value,
			Databases: splitStrings(p.Databases),
			Tags:      splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetSubdomainTakeover() *SubdomainTakeoverPayloadSet {
	payloads := l.GetPayloads("subdomain_takeover")
	if len(payloads) == 0 {
		return nil
	}

	set := &SubdomainTakeoverPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

func (l *Loader) GetClickjacking() *ClickjackingPayloadSet {
	payloads := l.GetPayloads("clickjacking")
	if len(payloads) == 0 {
		return nil
	}

	set := &ClickjackingPayloadSet{}
	for _, p := range payloads {
		set.Payloads = append(set.Payloads, PayloadEntry{
			Value: p.Value,
			Tags:  splitStrings(p.Tags),
		})
	}
	return set
}

type SQLiPayloadSet struct {
	ErrorPayloads   []PayloadEntry
	TimePayloads    []PayloadEntry
	UnionPayloads   []PayloadEntry
	BooleanPayloads []PayloadEntry
	BooleanPairs    []BooleanPair
	ErrorPatterns   []model.VulnPayloadPattern
}

type XSSPayloadSet struct {
	Payloads   []XSSPayloadEntry
	DOMSinks   []model.VulnPayloadPattern
	DOMSources []model.VulnPayloadPattern
}

type XSSPayloadEntry struct {
	Value   string
	Expect  string
	Context string
	Tags    []string
}

type CRLFPayloadSet struct {
	Payloads []PayloadEntry
	Params   []string
}

type HostHeaderPayloadSet struct {
	Payloads []PayloadEntry
}

type SSRFPayloadSet struct {
	Payloads []PayloadEntry
}

type CmdiPayloadSet struct {
	Payloads []PayloadEntry
}

type LFIPayloadSet struct {
	Payloads []PayloadEntry
}

type SSTIPayloadSet struct {
	Payloads []PayloadEntry
}

type XXEPayloadSet struct {
	Payloads []PayloadEntry
}

type NoSQLiPayloadSet struct {
	Payloads []PayloadEntry
}

type SensitiveDataPayloadSet struct {
	Patterns []PatternEntry
}

type PatternEntry struct {
	Pattern     string
	Name        string
	Description string
	Severity    string
}

type SessionFixationPayloadSet struct {
	Paths []string
}

type HTTPSmugglingPayloadSet struct {
	Payloads []PayloadEntry
	CLTEBody string
	TECLBody string
}

type XMLRPCPayloadSet struct {
	Payloads []PayloadEntry
}

type DirTraversalPayloadSet struct {
	Payloads []PayloadEntry
}

type OpenRedirectPayloadSet struct {
	Payloads []PayloadEntry
}

type FileUploadPayloadSet struct {
	Payloads []PayloadEntry
}

type DeserializationPayloadSet struct {
	Payloads []PayloadEntry
}

type AuthBypassPayloadSet struct {
	Payloads []PayloadEntry
}

type SubdomainTakeoverPayloadSet struct {
	Payloads []PayloadEntry
}

type ClickjackingPayloadSet struct {
	Payloads []PayloadEntry
}

type PayloadEntry struct {
	Value     string
	Databases []string
	Tags      []string
}

type BooleanPair struct {
	TruePayload  string
	FalsePayload string
}

func splitStrings(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func extractCRLFParam(value string) string {
	if idx := strings.Index(value, "Set-Cookie:"); idx >= 0 {
		return "Set-Cookie"
	}
	if idx := strings.Index(value, "Location:"); idx >= 0 {
		return "Location"
	}
	if idx := strings.Index(value, "Content-Type:"); idx >= 0 {
		return "Content-Type"
	}
	if idx := strings.Index(value, "X-XSS-Protection:"); idx >= 0 {
		return "X-XSS-Protection"
	}
	if idx := strings.Index(value, "X-CRLF-Test:"); idx >= 0 {
		return "X-CRLF-Test"
	}
	return ""
}
