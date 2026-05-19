package sitemonitor

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"vulnscan-backend/model"
	"vulnscan-backend/sitemonitor/contract"

	"gorm.io/gorm"
)

type assetMonitorSpec struct {
	targetType    string
	targetValue   string
	virtualHost   string
	defaultScheme string
	urlOverride   string
	path          string
}

func (s *serviceMonitor) CreateTasksFromAssets(
	ctx context.Context,
	assetIDs []string,
) (*contract.CreateTasksFromAssetsResp, []string, error) {
	resp := &contract.CreateTasksFromAssetsResp{
		Total:   len(assetIDs),
		Results: make([]contract.CreateTasksFromAssetsItem, 0, len(assetIDs)),
	}
	createdPathTaskIDs := make([]string, 0)
	if len(assetIDs) == 0 {
		return resp, createdPathTaskIDs, nil
	}

	defaults, _ := s.loadDefaultConfigs(ctx)
	session := s.session().WithContext(ctx)

	for _, assetID := range assetIDs {
		assetID = strings.TrimSpace(assetID)
		item := contract.CreateTasksFromAssetsItem{AssetID: assetID}
		if assetID == "" {
			item.Error = "资产 ID 为空"
			resp.Results = append(resp.Results, item)
			continue
		}

		var asset model.Asset
		if err := session.First(&asset, "id = ?", assetID).Error; err != nil {
			item.AssetName = assetID
			if err == gorm.ErrRecordNotFound {
				item.Error = "资产不存在"
			} else {
				item.Error = err.Error()
			}
			resp.Results = append(resp.Results, item)
			continue
		}
		item.AssetName = asset.Name

		var existing model.MonitorPathTask
		if err := session.Where("asset_id = ?", assetID).First(&existing).Error; err == nil {
			item.Skipped = true
			item.TaskID = existing.ID
			item.Reason = "该资产已有监测路径任务"
			resp.Results = append(resp.Results, item)
			continue
		}

		spec, err := parseAssetMonitorSpec(&asset)
		if err != nil {
			item.Error = err.Error()
			resp.Results = append(resp.Results, item)
			continue
		}

		targetID, err := s.ensureMonitorTargetForAsset(ctx, session, &asset, spec, defaults)
		if err != nil {
			item.Error = err.Error()
			resp.Results = append(resp.Results, item)
			continue
		}

		pt := &model.MonitorPathTask{
			TargetID: targetID,
			Name:     asset.Name,
			AssetID:  asset.ID,
			Enabled:  true,
		}
		if spec.urlOverride != "" {
			pt.URLOverride = spec.urlOverride
		} else {
			pt.Path = spec.path
			if pt.Path == "" {
				pt.Path = "/"
			}
		}
		applyPathTaskDefaultsFromConfigs(pt, defaults)

		if err := s.CreatePathTask(ctx, pt); err != nil {
			item.Error = err.Error()
			resp.Results = append(resp.Results, item)
			continue
		}

		item.Success = true
		item.TaskID = pt.ID
		resp.Success++
		createdPathTaskIDs = append(createdPathTaskIDs, pt.ID)
		resp.Results = append(resp.Results, item)
	}

	return resp, createdPathTaskIDs, nil
}

func (s *serviceMonitor) ensureMonitorTargetForAsset(
	ctx context.Context,
	session *gorm.DB,
	asset *model.Asset,
	spec assetMonitorSpec,
	defaults map[string]map[string]any,
) (string, error) {
	var target model.MonitorTarget
	if err := session.Where("asset_id = ?", asset.ID).First(&target).Error; err == nil {
		return target.ID, nil
	} else if err != gorm.ErrRecordNotFound {
		return "", err
	}

	target = model.MonitorTarget{
		Name:          asset.Name,
		TargetType:    spec.targetType,
		TargetValue:   spec.targetValue,
		DefaultScheme: spec.defaultScheme,
		VirtualHost:   spec.virtualHost,
		AssetID:       asset.ID,
		Enabled:       true,
	}
	if ip := strings.TrimSpace(asset.IPv4); ip != "" {
		target.ExpectedIPs = ip
	}
	for _, dim := range model.MonitorTargetDimensions {
		cfg := map[string]any{"enabled": true}
		if def, ok := defaults[dim]; ok {
			for k, v := range def {
				if k != "enabled" {
					cfg[k] = v
				}
			}
		}
		target.SetDimensionConfig(dim, cfg)
	}
	if err := s.CreateTarget(ctx, &target); err != nil {
		return "", err
	}
	return target.ID, nil
}

func applyPathTaskDefaultsFromConfigs(pt *model.MonitorPathTask, defaults map[string]map[string]any) {
	for _, dim := range model.MonitorPathDimensions {
		cfg := map[string]any{"enabled": true}
		if def, ok := defaults[dim]; ok {
			for k, v := range def {
				if k != "enabled" {
					cfg[k] = v
				}
			}
		}
		pt.SetDimensionConfig(dim, cfg)
	}
}

func parseAssetMonitorSpec(asset *model.Asset) (assetMonitorSpec, error) {
	spec := assetMonitorSpec{defaultScheme: "https", path: "/"}
	rawURL := strings.TrimSpace(firstNonEmpty(asset.URL, asset.Address))

	if strings.Contains(rawURL, "://") {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return spec, fmt.Errorf("无法解析访问地址")
		}
		spec.targetType = model.MonitorTargetTypeDomain
		spec.targetValue = u.Hostname()
		if u.Scheme != "" {
			spec.defaultScheme = u.Scheme
		}
		spec.urlOverride = rawURL
		return spec, nil
	}

	if d := strings.TrimSpace(asset.Domain); d != "" {
		spec.targetType = model.MonitorTargetTypeDomain
		spec.targetValue = d
		if asset.Port > 0 {
			spec.urlOverride = fmt.Sprintf("%s://%s:%d/", spec.defaultScheme, d, asset.Port)
		}
		return spec, nil
	}

	if ip := strings.TrimSpace(asset.IPv4); ip != "" {
		spec.targetType = model.MonitorTargetTypeIP
		spec.targetValue = ip
		vh := strings.TrimSpace(firstNonEmpty(asset.Domain, asset.Name))
		if vh == "" {
			return spec, fmt.Errorf("IP 资产需填写域名或资产名称作为虚拟 Host")
		}
		spec.virtualHost = vh
		port := asset.Port
		if port <= 0 {
			port = 80
		}
		if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
			if u := normalizeAssetHTTPURL(rawURL); u != "" {
				spec.urlOverride = u
			}
		} else if port == 443 {
			spec.urlOverride = fmt.Sprintf("https://%s/", vh)
			spec.defaultScheme = "https"
		} else {
			spec.urlOverride = fmt.Sprintf("http://%s:%d/", vh, port)
			spec.defaultScheme = "http"
		}
		return spec, nil
	}

	if rawURL != "" {
		if net.ParseIP(rawURL) != nil {
			spec.targetType = model.MonitorTargetTypeIP
			spec.targetValue = rawURL
			vh := strings.TrimSpace(asset.Name)
			if vh == "" {
				return spec, fmt.Errorf("IP 资产需填写资产名称作为虚拟 Host")
			}
			spec.virtualHost = vh
			return spec, nil
		}
		spec.targetType = model.MonitorTargetTypeDomain
		spec.targetValue = rawURL
		return spec, nil
	}

	return spec, fmt.Errorf("资产缺少可用访问地址（URL/域名/IP）")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func normalizeAssetHTTPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if strings.Contains(raw, "://") {
		return ""
	}
	return "http://" + raw
}
