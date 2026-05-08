package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var federationSecret = []byte("vulnscan-federation-default-secret-change-me")

func SetFederationSecret(s string) {
	if s != "" {
		federationSecret = []byte(s)
	}
}

// GenerateAPIToken creates a HMAC-SHA256 signed token for a sub-master.
func GenerateAPIToken(subMasterCode string) string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	nonceHex := hex.EncodeToString(nonce)

	payload := fmt.Sprintf("%s:%s:%d", subMasterCode, nonceHex, time.Now().Unix())
	mac := hmac.New(sha256.New, federationSecret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s.%s", payload, sig)
}

// ValidateAPIToken checks whether a token is valid and returns the sub-master code.
func ValidateAPIToken(token string) (string, bool) {
	idx := strings.LastIndex(token, ".")
	if idx < 0 {
		return "", false
	}

	payload := token[:idx]
	sig := token[idx+1:]

	mac := hmac.New(sha256.New, federationSecret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", false
	}

	parts := strings.SplitN(payload, ":", 3)
	if len(parts) < 3 {
		return "", false
	}

	return parts[0], true
}

// FederationAuthMiddleware enforces API token authentication on Federation endpoints.
// Registration endpoint bypasses authentication (token is obtained via registration).
func FederationAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, "/register") {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			return
		}

		subMasterCode, valid := ValidateAPIToken(token)
		if !valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("sub_master_code", subMasterCode)
		c.Next()
	}
}
