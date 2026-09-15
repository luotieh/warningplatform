package store

import (
	"fmt"
	"strings"
	"time"
)

// ArchiveRange validates inclusive calendar dates independently of event creation time.
func (q EventQuery) ArchiveRange() (string, string, error) {
	from, to := strings.TrimSpace(q.ArchiveFrom), strings.TrimSpace(q.ArchiveTo)
	if date := strings.TrimSpace(q.Date); date != "" {
		if from != "" || to != "" {
			return "", "", fmt.Errorf("date 不能与 archive_from/archive_to 同时使用")
		}
		from, to = date, date
	}
	for _, date := range []string{from, to} {
		if date == "" {
			continue
		}
		if _, err := time.Parse("2006-01-02", date); err != nil {
			return "", "", fmt.Errorf("归档日期必须为有效的 YYYY-MM-DD 日期")
		}
	}
	if from != "" && to != "" && from > to {
		return "", "", fmt.Errorf("归档开始日期不能晚于结束日期")
	}
	return from, to, nil
}
