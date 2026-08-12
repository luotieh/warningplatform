package traffic

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const successCode = 2000

func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{
		"code": successCode,
		"data": data,
		"msg":  "操作成功",
	})
}

func okMessage(c *gin.Context, message string, data any) {
	c.JSON(http.StatusOK, gin.H{
		"code": successCode,
		"data": data,
		"msg":  message,
	})
}

func authOK(c *gin.Context, token string, user any) {
	c.JSON(http.StatusOK, gin.H{
		"access_token": token,
		"code":         successCode,
		"data":         user,
		"msg":          "操作成功",
		"token_type":   "bearer",
		"user":         user,
	})
}

func fail(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{
		"code":    status,
		"message": message,
		"msg":     message,
	})
}

func readBody(c *gin.Context) (map[string]any, bool) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, err.Error())
		return nil, false
	}
	return body, true
}

func firstString(body map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := stringValue(body[key]); v != "" {
			return v
		}
	}
	return ""
}

func firstStringDefault(body map[string]any, fallback string, keys ...string) string {
	if v := firstString(body, keys...); v != "" {
		return v
	}
	return fallback
}

func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func intFromBody(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func boolFromBody(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "yes", "y", "on":
			return true
		}
	}
	return false
}
