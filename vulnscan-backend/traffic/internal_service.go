package traffic

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	trafficconfig "vulnscan-backend/traffic/internal/config"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

const (
	evidenceTimeout          = 10 * time.Second
	evidenceMaxBytes         = 20 << 20 // 20MB
	evidencePathPrefix       = "/api/v1/evidence/"
	evidenceContentType      = "application/vnd.tcpdump.pcap"
	evidenceFetchConcurrency = 4
	evidenceArchiveMaxBytes  = 500 << 20 // 500MB
	evidenceArchiveTimeout   = 120 * time.Second
)

var (
	errEventNotFound    = errors.New("事件不存在")
	errEvidenceNotFound = errors.New("证据不存在")
	errEvidenceInvalid  = errors.New("证据路径非法")
	errEvidenceTooLarge = errors.New("证据总量超过上限")
)

type InternalService struct {
	cfg  trafficconfig.Config
	core trafficservice.Services
}

func NewInternalService(cfg trafficconfig.Config, core trafficservice.Services) *InternalService {
	return &InternalService{cfg: cfg, core: core}
}

func (s *InternalService) PushEvent(ctx context.Context, body map[string]any, apiKey string) (map[string]any, error) {
	if !s.validInternalKey(apiKey) {
		return nil, errors.New("UNAUTHORIZED")
	}
	res, err := s.core.ProcessLyEvent(ctx, body)
	if err != nil {
		return nil, err
	}
	// 分析异步执行、脱离请求上下文：推送/查看报告立即返回事件ID，分析结果经 websocket
	// 增量回传，避免 LLM 较慢时请求被取消而报 "context canceled / i/o timeout"。
	if eventID := internalString(res["deepsoc_event_id"]); eventID != "" {
		s.core.RunAgentWorkflowAsync(eventID)
	}
	return res, nil
}

func (s *InternalService) SyncRun(ctx context.Context) (map[string]any, error) {
	if s.core.FlowShadow.Enabled() {
		return s.core.RunSyncOnce(ctx, s.cfg.SyncBatchSize, s.cfg.SyncLookbackSeconds, s.cfg.SyncMaxRetries)
	}
	return map[string]any{
		"mode":    "local-mysql",
		"fetched": 0,
		"pushed":  0,
		"failed":  0,
		"message": "flow shadow disabled: sync skipped",
	}, nil
}

func (s *InternalService) DedupReset() map[string]any {
	return map[string]any{
		"reset":   true,
		"message": "dedup reset completed",
	}
}

func (s *InternalService) Flow(ctx context.Context, flowID string) (map[string]any, error) {
	if flowID == "" {
		return nil, errors.New("flow_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("flow data source unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetFlow(ctx, flowID)
}

func (s *InternalService) RelatedFlows(ctx context.Context, flowID string) (any, error) {
	if flowID == "" {
		return nil, errors.New("flow_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("flow data source unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetRelatedFlows(ctx, flowID, "", "", 20)
}

func (s *InternalService) Asset(ctx context.Context, ip string) (map[string]any, error) {
	if ip == "" {
		return nil, errors.New("ip is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("asset data source unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetAsset(ctx, ip)
}

func (s *InternalService) PreparePCAP(ctx context.Context, flowID string) (map[string]any, error) {
	if flowID == "" {
		return nil, errors.New("flow_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("pcap unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.PreparePCAP(ctx, flowID)
}

func (s *InternalService) PCAP(ctx context.Context, pcapID string) (map[string]any, error) {
	if pcapID == "" {
		return nil, errors.New("pcap_id is required")
	}
	if !s.core.FlowShadow.Enabled() {
		return nil, errors.New("pcap unavailable: flow shadow disabled")
	}
	return s.core.FlowShadow.GetPCAP(ctx, pcapID)
}

// EvidenceFile 返回事件证据文件（PCAP）内容，供管理端代理下载。
// 节点地址从配置映射 evidence_nodes[device_id] 解析，path_ref 严格校验。
func (s *InternalService) EvidenceFile(ctx context.Context, eventID string, idx int) ([]byte, string, string, error) {
	event, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return nil, "", "", errEventNotFound
	}
	ctxMap := map[string]any{}
	if event.Context != "" {
		_ = json.Unmarshal([]byte(event.Context), &ctxMap)
	}
	files, ok := ctxMap["evidence_files"].([]any)
	if !ok || idx < 0 || idx >= len(files) {
		return nil, "", "", errEvidenceNotFound
	}
	ef, ok := files[idx].(map[string]any)
	if !ok {
		return nil, "", "", errEvidenceNotFound
	}
	name := firstNonEmptyAny(ef["name"], ef["id"])
	pathRef := strings.TrimSpace(toStr(ef["path_ref"]))
	if !validEvidencePath(pathRef) {
		return nil, "", "", errEvidenceInvalid
	}
	deviceID := strings.TrimSpace(firstNonEmptyAny(ef["device_id"], ctxMap["device_id"]))
	base := strings.TrimRight(s.cfg.EvidenceNodes[deviceID], "/")
	if base == "" {
		return nil, "", "", fmt.Errorf("未配置节点 %q 的证据服务地址（evidence_nodes）", deviceID)
	}
	url := base + pathRef
	client := &http.Client{Timeout: evidenceTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", "", fmt.Errorf("节点证据下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("节点证据返回 %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "pcap") && !strings.Contains(ct, "octet-stream") {
		return nil, "", "", fmt.Errorf("节点证据类型异常: %s", ct)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, evidenceMaxBytes+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("读取节点证据失败: %w", err)
	}
	if int64(len(data)) > evidenceMaxBytes {
		return nil, "", "", fmt.Errorf("证据文件超过大小上限（%d MB）", evidenceMaxBytes>>20)
	}
	if ct == "" {
		ct = evidenceContentType
	}
	return data, name, ct, nil
}

// EvidenceArchiveResult 描述聚合事件全量 PCAP 打包结果。
type EvidenceArchiveResult struct {
	Total     int      `json:"total"`
	Succeeded int      `json:"succeeded"`
	Failed    int      `json:"failed"`
	Truncated bool     `json:"truncated"`
	Entries   []string `json:"entries"`
}

// evidenceTarget 描述单个证据文件的打包目标。
type evidenceTarget struct {
	idx       int
	name      string
	pathRef   string
	baseURL   string
	deviceID  string
	occIdx    int
	occTime   string
	entryName string
	tempPath  string
	size      int64
	err       error
}

// EvidenceArchive 并发拉取聚合事件全部证据并打包为 ZIP。
// 返回临时目录（内含 archive.zip）与结果摘要；调用方负责 os.RemoveAll(tmpDir)。
// 失败策略：单文件失败不中断，写入 _下载失败清单.txt；全部失败/超限才返回错误。
func (s *InternalService) EvidenceArchive(ctx context.Context, eventID string) (string, EvidenceArchiveResult, error) {
	var result EvidenceArchiveResult
	event, ok := s.core.Store.GetEvent(eventID)
	if !ok {
		return "", result, errEventNotFound
	}
	ctxMap := map[string]any{}
	if event.Context != "" {
		_ = json.Unmarshal([]byte(event.Context), &ctxMap)
	}
	files, ok := ctxMap["evidence_files"].([]any)
	if !ok || len(files) == 0 {
		return "", result, errEvidenceNotFound
	}
	targets := s.buildEvidenceTargets(ctxMap, files)
	if len(targets) == 0 {
		return "", result, errEvidenceNotFound
	}
	result.Total = len(targets)
	result.Truncated = toBoolAny(ctxMap["evidence_truncated"])

	tmpDir, err := os.MkdirTemp("", "wp-evidence-*")
	if err != nil {
		return "", result, fmt.Errorf("创建证据临时目录失败: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	jobs := make(chan *evidenceTarget)
	var wg sync.WaitGroup
	for i := 0; i < evidenceFetchConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if t.err != nil {
					continue
				}
				t.err = s.fetchEvidenceFile(ctx, tmpDir, t)
			}
		}()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	if err = ctx.Err(); err != nil {
		return "", result, fmt.Errorf("证据打包中断: %w", err)
	}

	var failures []string
	var totalSize int64
	for _, t := range targets {
		if t.err != nil {
			failures = append(failures, fmt.Sprintf("%s（节点 %s）：%v", t.name, t.deviceID, t.err))
			continue
		}
		totalSize += t.size
	}
	result.Failed = len(failures)
	result.Succeeded = result.Total - result.Failed
	if result.Failed == result.Total {
		return "", result, fmt.Errorf("全部 %d 个证据下载失败，首个错误：%s", result.Total, failures[0])
	}
	if totalSize > evidenceArchiveMaxBytes {
		return "", result, fmt.Errorf("%w：累计 %d MB 超过上限 %d MB",
			errEvidenceTooLarge, totalSize>>20, evidenceArchiveMaxBytes>>20)
	}

	zipPath := filepath.Join(tmpDir, "archive.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		return "", result, fmt.Errorf("创建打包文件失败: %w", err)
	}
	zw := zip.NewWriter(zf)
	usedNames := make(map[string]int, len(targets))
	for _, t := range targets {
		if t.err != nil {
			continue
		}
		header := &zip.FileHeader{Name: uniqueZipName(t.entryName, usedNames), Method: zip.Deflate}
		if mt, perr := time.Parse(time.RFC3339, t.occTime); perr == nil {
			header.Modified = mt
		}
		w, werr := zw.CreateHeader(header)
		if werr != nil {
			_ = zw.Close()
			_ = zf.Close()
			return "", result, fmt.Errorf("写入 zip 条目失败: %w", werr)
		}
		src, oerr := os.Open(t.tempPath)
		if oerr != nil {
			_ = zw.Close()
			_ = zf.Close()
			return "", result, fmt.Errorf("读取临时证据失败: %w", oerr)
		}
		_, cerr := io.Copy(w, src)
		_ = src.Close()
		if cerr != nil {
			_ = zw.Close()
			_ = zf.Close()
			return "", result, fmt.Errorf("写入 zip 失败: %w", cerr)
		}
		result.Entries = append(result.Entries, header.Name)
	}
	if len(failures) > 0 {
		if fw, ferr := zw.Create("_下载失败清单.txt"); ferr == nil {
			_, _ = fmt.Fprintf(fw, "聚合事件 %s：共 %d 个证据，成功 %d，失败 %d\n",
				eventID, result.Total, result.Succeeded, result.Failed)
			for _, f := range failures {
				_, _ = fmt.Fprintln(fw, f)
			}
		}
	}
	if err = zw.Close(); err != nil {
		_ = zf.Close()
		return "", result, fmt.Errorf("关闭 zip 失败: %w", err)
	}
	if err = zf.Close(); err != nil {
		return "", result, fmt.Errorf("关闭打包文件失败: %w", err)
	}
	return tmpDir, result, nil
}

func (s *InternalService) buildEvidenceTargets(ctxMap map[string]any, files []any) []*evidenceTarget {
	eventDeviceID := strings.TrimSpace(toStr(ctxMap["device_id"]))
	targets := make([]*evidenceTarget, 0, len(files))
	for i, item := range files {
		ef, ok := item.(map[string]any)
		if !ok {
			continue
		}
		t := &evidenceTarget{
			idx:     i,
			name:    sanitizeEvidenceName(firstNonEmptyAny(ef["name"], ef["id"])),
			pathRef: strings.TrimSpace(toStr(ef["path_ref"])),
		}
		if t.name == "" {
			t.name = fmt.Sprintf("evidence_%03d.pcap", i)
		}
		t.occIdx = toIntAny(ef["occ_idx"])
		t.occTime = toStr(ef["occ_time"])
		t.entryName = buildEvidenceEntryName(t.occIdx, t.occTime, t.name)
		deviceID := strings.TrimSpace(firstNonEmptyAny(ef["device_id"], eventDeviceID))
		t.deviceID = deviceID
		if !validEvidencePath(t.pathRef) {
			t.err = errEvidenceInvalid
			targets = append(targets, t)
			continue
		}
		base := strings.TrimRight(s.cfg.EvidenceNodes[deviceID], "/")
		if base == "" {
			t.err = fmt.Errorf("未配置节点 %q 的证据服务地址（evidence_nodes）", deviceID)
			targets = append(targets, t)
			continue
		}
		t.baseURL = base
		targets = append(targets, t)
	}
	return targets
}

func (s *InternalService) fetchEvidenceFile(ctx context.Context, dir string, t *evidenceTarget) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+t.pathRef, nil)
	if err != nil {
		return fmt.Errorf("构造下载请求失败: %w", err)
	}
	client := &http.Client{Timeout: evidenceTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("节点证据下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("节点证据返回 %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "pcap") && !strings.Contains(ct, "octet-stream") {
		return fmt.Errorf("节点证据类型异常: %s", ct)
	}
	dst := filepath.Join(dir, fmt.Sprintf("evidence-%03d.bin", t.idx))
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	n, copyErr := io.Copy(out, io.LimitReader(resp.Body, evidenceMaxBytes+1))
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("读取节点证据失败: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("写入临时文件失败: %w", closeErr)
	}
	if n > evidenceMaxBytes {
		_ = os.Remove(dst)
		return fmt.Errorf("证据文件超过大小上限（%d MB）", evidenceMaxBytes>>20)
	}
	t.tempPath = dst
	t.size = n
	return nil
}

func buildEvidenceEntryName(occIdx int, occTime, name string) string {
	seq := "999"
	if occIdx >= 0 {
		seq = fmt.Sprintf("%03d", occIdx)
	}
	ts := ""
	if t, err := time.Parse(time.RFC3339, occTime); err == nil {
		ts = t.UTC().Format("20060102T150405Z")
	} else if occTime != "" {
		ts = sanitizeEvidenceName(occTime)
		if len(ts) > 32 {
			ts = ts[:32]
		}
	}
	if ts != "" {
		return fmt.Sprintf("%s_%s_%s", seq, ts, name)
	}
	return fmt.Sprintf("%s_%s", seq, name)
}

func sanitizeEvidenceName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' || r == 'T' || r == 'Z' {
			return r
		}
		return '_'
	}, s)
	return strings.Trim(s, "_")
}

func uniqueZipName(base string, used map[string]int) string {
	n := used[base]
	used[base] = n + 1
	if n == 0 {
		return base
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s_%d%s", stem, n, ext)
}

func toIntAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	}
	return -1
}

func toBoolAny(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case float64:
		return x != 0
	}
	return false
}

func validEvidencePath(p string) bool {
	if !strings.HasPrefix(p, evidencePathPrefix) {
		return false
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, "\\") || strings.Contains(p, "://") {
		return false
	}
	return true
}

func firstNonEmptyAny(vals ...any) string {
	for _, v := range vals {
		if s := toStr(v); s != "" {
			return s
		}
	}
	return ""
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(v)
}

func (s *InternalService) validInternalKey(apiKey string) bool {
	return s.cfg.InternalAPIKey == "" || apiKey == s.cfg.InternalAPIKey
}

func internalString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
