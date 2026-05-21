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
	)
	if strings.TrimSpace(data.IncidentURL) != "" {
		rows = append(rows, [4]string{"隐患URL", dashField(data.IncidentURL), "", ""})
	}
	if hasAny(data.AssetName, data.DomainIP, data.SiteIP, data.Region) {
		rows = append(rows, [4]string{
			"网站名称", dashField(data.AssetName),
			"网站域名IP", dashField(data.DomainIP),
		})
		rows = append(rows, [4]string{"网站IP", dashField(data.SiteIP), "归属地", dashField(data.Region)})
	}
	rows = append(rows,
		[4]string{"隐患类型", dashField(data.IncidentType), "预警级别", dashField(data.WarningLevel)},
		[4]string{"隐患级别", dashField(data.Level), "发现时间", dashField(data.DiscoveryTime)},
		[4]string{"上报厂商", dashField(data.VendorName), "厂商上报时间", dashField(data.VendorTime)},
	)
	if hasAny(data.Unit, data.UnitType, data.Industry, data.MLPSLevel) {
		rows = append(rows, [4]string{
			"隶属单位", dashField(data.Unit),
			"单位类型", dashField(data.UnitType),
		})
		rows = append(rows, [4]string{"所属行业", dashField(data.Industry), "等保级别", dashField(data.MLPSLevel)})
	}
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
