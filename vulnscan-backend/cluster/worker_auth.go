package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	workerTokenHeader = "X-Worker-Token"
	tokenTTL          = 24 * time.Hour
)

var workerSecret = []byte("vs-worker-secret-change-in-production")

// SetWorkerSecret allows overriding the default secret from config.
func SetWorkerSecret(secret string) {
	if secret != "" {
		workerSecret = []byte(secret)
	}
}

// GenerateWorkerToken creates an HMAC-SHA256 token for a worker.
// Format: workerID:expiry:signature
func GenerateWorkerToken(workerID string) string {
	expiry := time.Now().Add(tokenTTL).Unix()
	payload := fmt.Sprintf("%s:%d", workerID, expiry)
	sig := signPayload(payload)
	return fmt.Sprintf("%s:%s", payload, sig)
}

// ValidateWorkerToken verifies the token and returns the workerID if valid.
func ValidateWorkerToken(token string) (string, error) {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	workerID := parts[0]
	payload := parts[0] + ":" + parts[1]
	sig := parts[2]

	expectedSig := signPayload(payload)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid token signature")
	}

	var expiry int64
	if _, err := fmt.Sscanf(parts[1], "%d", &expiry); err != nil {
		return "", fmt.Errorf("invalid expiry")
	}
	if time.Now().Unix() > expiry {
		return "", fmt.Errorf("token expired")
	}

	return workerID, nil
}

func signPayload(payload string) string {
	mac := hmac.New(sha256.New, workerSecret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// WorkerAuthMiddleware validates the X-Worker-Token header on cluster API routes.
func WorkerAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader(workerTokenHeader)
		if token == "" {
			token = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		}

		if token == "" {
			if strings.HasSuffix(c.Request.URL.Path, "/register") {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "缺少 Worker 认证令牌"})
			return
		}

		workerID, err := ValidateWorkerToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "令牌无效: " + err.Error()})
			return
		}

		c.Set("worker_id", workerID)
		c.Next()
	}
}
