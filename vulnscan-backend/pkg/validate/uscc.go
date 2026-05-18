package validate

import (
	"fmt"
	"strings"
)

// GB 32100-2015 统一社会信用代码字符集（31 位，不含 I O S V Z）。
const usccCharset = "0123456789ABCDEFGHJKLMNPQRTUWXY"

var usccWeights = [17]int{1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28}

// USCC 校验 18 位统一社会信用代码（含校验位）；空字符串通过。
func USCC(raw string) error {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if code == "" {
		return nil
	}
	if len(code) != 18 {
		return fmt.Errorf("统一社会信用代码须为 18 位")
	}
	for i := 0; i < 17; i++ {
		if usccCharIndex(code[i]) < 0 {
			return fmt.Errorf("统一社会信用代码含有非法字符")
		}
	}
	check := code[17]
	if checkIdx := usccCharIndex(check); checkIdx < 0 {
		return fmt.Errorf("统一社会信用代码校验位无效")
	} else if checkIdx != usccCheckIndex(code[:17]) {
		return fmt.Errorf("统一社会信用代码校验位不正确")
	}
	return nil
}

func usccCharIndex(ch byte) int {
	return strings.IndexByte(usccCharset, ch)
}

func usccCheckIndex(body string) int {
	sum := 0
	for i := 0; i < 17; i++ {
		idx := usccCharIndex(body[i])
		if idx < 0 {
			return -1
		}
		sum += idx * usccWeights[i]
	}
	return (31 - sum%31) % 31
}
