package traffic

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/xuri/excelize/v2"

	"vulnscan-backend/traffic/internal/domain"
	"vulnscan-backend/traffic/internal/store"
)

type AssetService struct {
	store store.Store
}

func NewAssetService(st store.Store) *AssetService {
	return &AssetService{store: st}
}

type AssetImportError struct {
	Row     int    `json:"row"`
	Message string `json:"message"`
}

func (s *AssetService) List() []domain.Asset { return s.store.ListAssets() }

func (s *AssetService) Create(in domain.Asset) (domain.Asset, error) {
	in.AssetType = normalizeAssetType(in.AssetType)
	in.Address = normalizeAddrForType(in.AssetType, in.Address)
	in.Name = strings.TrimSpace(in.Name)
	if err := validateAsset(in); err != nil {
		return domain.Asset{}, err
	}
	return s.store.CreateAsset(in)
}

func (s *AssetService) Update(id string, patch map[string]any) (domain.Asset, bool, error) {
	if v, ok := patch["asset_type"]; ok {
		patch["asset_type"] = normalizeAssetType(fmt.Sprint(v))
	}
	if v, ok := patch["address"]; ok {
		// 地址归一化依赖资产类型（网段不能截断 "/"），取 patch 中的新类型，
		// 未修改类型时回退当前存量类型。
		typ := ""
		if t, ok := patch["asset_type"]; ok {
			typ = fmt.Sprint(t)
		} else if cur, found := s.store.GetAsset(id); found {
			typ = cur.AssetType
		}
		patch["address"] = normalizeAddrForType(typ, fmt.Sprint(v))
	}
	// 组装校验用快照
	cur, ok := s.store.GetAsset(id)
	if !ok {
		return domain.Asset{}, false, nil
	}
	merged := cur
	if v, ok := patch["name"]; ok {
		merged.Name = strings.TrimSpace(fmt.Sprint(v))
		patch["name"] = merged.Name
	}
	if v, ok := patch["asset_type"]; ok {
		merged.AssetType = fmt.Sprint(v)
	}
	if v, ok := patch["address"]; ok {
		merged.Address = fmt.Sprint(v)
	}
	if err := validateAsset(merged); err != nil {
		return domain.Asset{}, false, err
	}
	updated, ok := s.store.UpdateAsset(id, patch)
	return updated, ok, nil
}

func (s *AssetService) Delete(id string) bool { return s.store.DeleteAsset(id) }

func normalizeAssetType(raw string) string {
	// ToLower 对中文无副作用，"IP资产"→"ip资产"、"域名网站" 均在此命中。
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "ip", "ip资产":
		return "ip"
	case "domain_site", "域名网站", "domain", "website", "site":
		return "domain_site"
	case "ip_segment", "网段", "ip网段", "网段资产", "cidr", "subnet", "ip_range":
		return "ip_segment"
	}
	return strings.TrimSpace(strings.ToLower(raw))
}

// normalizeAddrForType 按资产类型归一化地址：网段保留 "/" 并转为规范 CIDR，
// 其余类型沿用去 scheme/路径的主机归一化。
func normalizeAddrForType(assetType, raw string) string {
	if normalizeAssetType(assetType) == "ip_segment" {
		if cidr, err := canonicalCIDR(raw); err == nil {
			return cidr
		}
		return strings.TrimSpace(strings.ToLower(raw))
	}
	return normalizeAddr(raw)
}

func normalizeAddr(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	// 去掉 URL scheme 与路径，只留主机（域名资产友好）
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// canonicalCIDR 把网段写法转为规范 CIDR（网络基址/前缀长度）：
// 支持 "192.168.1.0/24" 与点分掩码 "36.154.169.2/255.255.255.224"（→ 36.154.169.0/27）。
func canonicalCIDR(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	slash := strings.Index(v, "/")
	if slash < 0 {
		return "", errors.New("缺少 / 前缀长度或掩码")
	}
	ipPart := strings.TrimSpace(v[:slash])
	maskPart := strings.TrimSpace(v[slash+1:])
	if strings.Contains(maskPart, ".") {
		maskIP := net.ParseIP(maskPart)
		if maskIP == nil || maskIP.To4() == nil {
			return "", fmt.Errorf("掩码非法: %s", maskPart)
		}
		ones, bits := net.IPMask(maskIP.To4()).Size()
		if bits == 0 {
			return "", fmt.Errorf("掩码非连续位: %s", maskPart)
		}
		maskPart = fmt.Sprint(ones)
	}
	_, ipnet, err := net.ParseCIDR(ipPart + "/" + maskPart)
	if err != nil {
		return "", err
	}
	return ipnet.String(), nil
}

func validateAsset(a domain.Asset) error {
	if a.Name == "" {
		return errors.New("资产名称不能为空")
	}
	if a.Address == "" {
		return errors.New("地址不能为空")
	}
	switch a.AssetType {
	case "ip":
		if net.ParseIP(a.Address) == nil {
			return errors.New("IP 地址格式非法")
		}
	case "domain_site":
		if !strings.Contains(a.Address, ".") || strings.ContainsAny(a.Address, " ") {
			return errors.New("域名格式非法")
		}
	case "ip_segment":
		if _, err := canonicalCIDR(a.Address); err != nil {
			return errors.New("网段格式非法（应为 CIDR 如 192.168.1.0/24，或 IP/点分掩码）")
		}
	default:
		return errors.New("资产类型必须为 ip、domain_site 或 ip_segment")
	}
	return nil
}

var assetImportHeaders = []string{"资产名称", "资产类型", "地址", "所属单位", "责任人", "备注"}

// Import 解析 csv/xlsx 并逐行导入；返回成功数与逐行错误（行号从 1 起、含表头行）。
func (s *AssetService) Import(filename string, data []byte) (int, []AssetImportError) {
	rows, err := parseAssetRows(filename, data)
	if err != nil {
		return 0, []AssetImportError{{Row: 0, Message: err.Error()}}
	}
	imported := 0
	errs := []AssetImportError{}
	for i, r := range rows {
		rowNum := i + 2 // +1 表头 +1 从1计
		if len(r) == 0 || strings.TrimSpace(strings.Join(r, "")) == "" {
			continue
		}
		a := domain.Asset{
			Name:      field(r, 0),
			AssetType: field(r, 1),
			Address:   field(r, 2),
			Unit:      field(r, 3),
			Owner:     field(r, 4),
			Remark:    field(r, 5),
			Status:    1, // 导入资产默认启用
		}
		if _, err := s.Create(a); err != nil {
			errs = append(errs, AssetImportError{Row: rowNum, Message: err.Error()})
			continue
		}
		imported++
	}
	return imported, errs
}

func field(r []string, i int) string {
	if i < len(r) {
		return strings.TrimSpace(r[i])
	}
	return ""
}

// parseAssetRows 返回不含表头的数据行。
func parseAssetRows(filename string, data []byte) ([][]string, error) {
	lower := strings.ToLower(strings.TrimSpace(filename))
	if strings.HasSuffix(lower, ".xlsx") {
		f, err := excelize.OpenReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("解析 xlsx 失败: %w", err)
		}
		defer f.Close()
		sheets := f.GetSheetList()
		if len(sheets) == 0 {
			return nil, errors.New("xlsx 无工作表")
		}
		all, err := f.GetRows(sheets[0])
		if err != nil {
			return nil, err
		}
		if len(all) <= 1 {
			return [][]string{}, nil
		}
		return all[1:], nil
	}
	// 默认按 CSV
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	all, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("解析 csv 失败: %w", err)
	}
	if len(all) <= 1 {
		return [][]string{}, nil
	}
	return all[1:], nil
}

// AssetImportTemplateCSV 返回导入模板 CSV 字节（带表头与一行示例）。
func AssetImportTemplateCSV() []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write(assetImportHeaders)
	_ = w.Write([]string{"示例网站", "域名网站", "example.com", "单位甲", "张三", "关注资产"})
	_ = w.Write([]string{"示例主机", "IP资产", "10.0.0.9", "单位乙", "李四", ""})
	_ = w.Write([]string{"示例网段", "网段资产", "192.168.10.0/24", "单位丙", "王五", "出口网段"})
	w.Flush()
	return b.Bytes()
}
