package asset

import (
	"errors"
	"fmt"
	"strings"

	"vulnscan-backend/pkg/dberr"
)

func formatImportRowError(row int, err error) string {
	if err == nil {
		return fmt.Sprintf("第 %d 行：导入失败", row)
	}
	return fmt.Sprintf("第 %d 行：%s", row, importUserFacingError(err))
}

func importUserFacingError(err error) string {
	if err == nil {
		return "导入失败"
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "导入失败"
	}

	if name, inner := parseWrappedOrganizeCreateError(msg); name != "" {
		if friendly := friendlyConstraintMessage(inner); friendly != "" {
			return fmt.Sprintf("创建单位「%s」失败：%s", name, friendly)
		}
	}

	if friendly := friendlyConstraintMessage(msg); friendly != "" {
		return friendly
	}
	return msg
}

func parseWrappedOrganizeCreateError(msg string) (name string, inner string) {
	const prefix = "创建单位「"
	if !strings.HasPrefix(msg, prefix) {
		return "", ""
	}
	rest := msg[len(prefix):]
	end := strings.Index(rest, "」")
	if end < 0 {
		return "", ""
	}
	name = rest[:end]
	after := strings.TrimSpace(rest[end+len("」"):])
	for _, sep := range []string{"失败:", "失败："} {
		if strings.HasPrefix(after, sep) {
			return name, strings.TrimSpace(after[len(sep):])
		}
	}
	return name, ""
}

func friendlyConstraintMessage(msg string) string {
	return dberr.FriendlyConstraint(msg)
}

func importOrganizeCreateError(name string, err error) error {
	if err == nil {
		return nil
	}
	if friendly := friendlyConstraintMessage(err.Error()); friendly != "" {
		return fmt.Errorf("创建单位「%s」失败：%s", name, friendly)
	}
	return fmt.Errorf("创建单位「%s」失败: %w", name, err)
}

// importDBError 将数据库错误转为可读说明（保留原始 err 供日志）。
func importDBError(action string, err error) error {
	if err == nil {
		return nil
	}
	if friendly := friendlyConstraintMessage(err.Error()); friendly != "" {
		return errors.New(action + "：" + friendly)
	}
	return fmt.Errorf("%s：%w", action, err)
}
