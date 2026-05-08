package definition

import (
	"net/http"

	"code.yt-security.com/public/core/v2/web"
)

// 30000-30999: 扫描模块
var (
	ScanTaskCreated     = web.Code{BusinessCode: 2000, HttpCode: http.StatusOK, Msg: "任务已加入队列"}
	ScanTaskCancelled   = web.Code{BusinessCode: 2000, HttpCode: http.StatusOK, Msg: "任务取消指令已发送"}
	ScanTaskNotFound    = web.Code{BusinessCode: 30001, HttpCode: http.StatusNotFound, Msg: "扫描任务不存在"}
	ScanCreateFailed    = web.Code{BusinessCode: 30002, HttpCode: http.StatusInternalServerError, Msg: "创建任务失败"}
	ScanReportFailed    = web.Code{BusinessCode: 30003, HttpCode: http.StatusInternalServerError, Msg: "生成报告失败"}
	ScanReportBadParams = web.Code{BusinessCode: 30004, HttpCode: http.StatusBadRequest, Msg: "报告参数错误"}
)
