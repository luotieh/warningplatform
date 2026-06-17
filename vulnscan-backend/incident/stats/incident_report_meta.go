package stats

import (
	"strings"

	statsContract "vulnscan-backend/incident/stats/stats-contract"
)

func incidentReportMetaRows(data *statsContract.IncidentReportData) [][4]string {
	var rows [][4]string
	rows = append(rows,
		[4]string{"隐患编号", dashField(data.IncidentNo), "数据编号", dashField(data.DataNo)},
		[4]string{"隐患名称", dashField(data.Name), "", ""},
		[4]string{"厂商上报归属地", dashField(data.VendorRegion), "", ""},
		[4]string{"隐患URL", dashField(data.IncidentURL), "", ""},
	)
	rows = append(rows,
		[4]string{"网站名称", dashField(data.AssetName), "网站域名IP", dashField(data.DomainIP)},
		[4]string{"网站IP", dashField(data.SiteIP), "归属地", dashField(data.Region)},
		[4]string{"隐患类型", dashField(data.IncidentType), "预警级别", dashField(data.WarningLevel)},
		[4]string{"隐患级别", dashField(data.Level), "发现时间", dashField(data.DiscoveryTime)},
		[4]string{"上报厂商", dashField(data.VendorName), "厂商上报时间", dashField(data.VendorTime)},
		[4]string{"涉及信息数量", dashField(data.AffectedCount), "涉及信息类型", dashField(data.AffectedType)},
		[4]string{"隶属单位", dashField(data.Unit), "单位类型", dashField(data.UnitType)},
		[4]string{"所属行业", dashField(data.Industry), "工信部备案号", dashField(data.MIITRecordNo)},
		[4]string{"等保级别", dashField(data.MLPSLevel), "等保备案号", dashField(data.MLPSRecordNo)},
	)
	return rows
}

func dashField(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func hasAny(vals ...string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
