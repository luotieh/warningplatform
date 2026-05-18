package asset

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestImportUserFacingErrorUSCCUnique(t *testing.T) {
	raw := errors.New(`constraint failed: UNIQUE constraint failed: vs_organize.unified_social_credit_code (2067)`)
	wrapped := fmt.Errorf("创建单位「测试单位2」失败: %w", raw)
	got := importUserFacingError(wrapped)
	if !strings.Contains(got, "统一社会信用代码") {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestImportOrganizeCreateError(t *testing.T) {
	raw := errors.New(`constraint failed: UNIQUE constraint failed: vs_organize.unified_social_credit_code (2067)`)
	got := importOrganizeCreateError("测试单位1", raw)
	if strings.Contains(got.Error(), "constraint failed") {
		t.Fatalf("expected friendly, got %q", got.Error())
	}
}

func TestFormatImportRowError(t *testing.T) {
	got := formatImportRowError(3, errors.New("统一社会信用代码与系统中已有单位重复"))
	if got != "第 3 行：统一社会信用代码与系统中已有单位重复" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatImportRowErrorPlainOrganizeCreate(t *testing.T) {
	raw := `创建单位「测试单位1」失败: constraint failed: UNIQUE constraint failed: vs_organize.unified_social_credit_code (2067)`
	got := formatImportRowError(3, errors.New(raw))
	if strings.Contains(got, "constraint failed") {
		t.Fatalf("expected friendly message, got %q", got)
	}
	if !strings.Contains(got, "统一社会信用代码") {
		t.Fatalf("expected USCC hint, got %q", got)
	}
}
