package validate

import "fmt"

// Port 校验端口：0 表示未填写；否则须为 1–65535。
func Port(port int) error {
	if port == 0 {
		return nil
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口须在 1–65535 之间")
	}
	return nil
}
