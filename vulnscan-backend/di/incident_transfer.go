package di

import "log/slog"

// wireIncidentReportExporter 将安全事件报告导出能力注入通报流转，便于转通报时附带 Word/PDF。
func (h *Handlers) wireIncidentReportExporter() {
	if h.Circular == nil || h.Incident == nil {
		return
	}
	h.Circular.TransferService().SetIncidentReportExporter(h.Incident.StatsService())
	slog.Info("[+] 安全事件报告已接入通报流转")
}
