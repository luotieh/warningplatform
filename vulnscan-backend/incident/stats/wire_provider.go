package stats

import (
	statsContract "vulnscan-backend/incident/stats/stats-contract"
	"vulnscan-backend/sitemonitor"

	"code.yt-security.com/public/core/v2/db"
)

// ProvideServiceStats 注入站点监测对象存储，用于导出报告时嵌入截图等证据。
func ProvideServiceStats(database *db.DB, monitor *sitemonitor.Monitor) statsContract.ServiceStats {
	var store reportObjectStore
	if monitor != nil {
		if ns := monitor.GetNatsService(); ns != nil {
			store = ns
		}
	}
	return NewServiceStats(database, store)
}
