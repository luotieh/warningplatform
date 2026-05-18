package validate

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	cnMobileRe   = regexp.MustCompile(`^1[3-9]\d{9}$`)
	cnLandlineRe = regexp.MustCompile(`^0\d{10,11}$`)
)

// CNPhone 校验中国大陆手机号或固话；空字符串通过。
func CNPhone(raw string) error {
	s := normalizePhoneInput(raw)
	if s == "" {
		return nil
	}
	if cnMobileRe.MatchString(s) {
		return nil
	}
	if cnLandlineRe.MatchString(s) {
		return nil
	}
	return fmt.Errorf("电话号码格式不正确，请填写 11 位手机号或带区号的固话")
}

func normalizePhoneInput(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	if strings.HasPrefix(s, "+86") {
		s = s[3:]
	} else if strings.HasPrefix(s, "86") && len(s) > 11 {
		s = s[2:]
	}
	return s
}
