package agent

import "strings"

// trimMasterURL 仅去除首尾空白与末尾斜杠，不修改路径内容。
func trimMasterURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}
