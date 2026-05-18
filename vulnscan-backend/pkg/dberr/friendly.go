package dberr

import "strings"

// FriendlyConstraint 将常见数据库唯一约束错误转为可读中文说明。
func FriendlyConstraint(msg string) string {
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "unified_social_credit_code") &&
		(strings.Contains(lower, "unique") || strings.Contains(strings.ToUpper(msg), "UNIQUE") || strings.Contains(msg, "(2067)")) {
		return "统一社会信用代码与系统中已有单位重复；若无代码请留空，勿重复填写其它单位已使用的代码"
	}
	if strings.Contains(lower, "unique constraint") ||
		strings.Contains(strings.ToUpper(msg), "UNIQUE CONSTRAINT") ||
		(strings.Contains(lower, "constraint failed") && strings.Contains(lower, "unique")) {
		return "填写内容与系统已有记录冲突，请检查是否重复"
	}
	return ""
}

// UserFacing 优先返回友好约束说明，否则返回原始错误文本。
func UserFacing(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	msg := strings.TrimSpace(err.Error())
	if friendly := FriendlyConstraint(msg); friendly != "" {
		return friendly
	}
	if msg == "" {
		return fallback
	}
	return msg
}
