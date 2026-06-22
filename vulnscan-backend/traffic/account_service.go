package traffic

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"vulnscan-backend/traffic/internal/domain"
	trafficservice "vulnscan-backend/traffic/internal/service"
)

type AccountService struct {
	core   trafficservice.Services
	mu     sync.RWMutex
	tokens map[string]string
}

func NewAccountService(core trafficservice.Services) *AccountService {
	return &AccountService{
		core:   core,
		tokens: map[string]string{},
	}
}

func (s *AccountService) Login(username string, password string) (string, domain.User, error) {
	u, ok := s.core.Store.GetUserByUsername(username)
	if !ok || !u.IsActive || (u.Password != "" && password != u.Password) {
		return "", domain.User{}, errors.New("用户名或密码错误")
	}
	token := randomAccessToken()
	s.mu.Lock()
	s.tokens[token] = u.UserID
	s.mu.Unlock()
	now := time.Now().UTC()
	updated, _ := s.core.Store.UpdateUser(u.UserID, map[string]any{"last_login_at": now})
	return token, updated, nil
}

func (s *AccountService) Logout(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

func (s *AccountService) CurrentUser(authHeader string) (domain.User, bool) {
	token := tokenFromAuthHeader(authHeader)
	if token == "" {
		return domain.User{}, false
	}
	s.mu.RLock()
	userID, ok := s.tokens[token]
	s.mu.RUnlock()
	if !ok {
		return domain.User{}, false
	}
	return s.core.Store.GetUser(userID)
}

func (s *AccountService) InitAdmin(body map[string]any) (domain.User, bool, error) {
	u := domain.User{
		UserID:   firstStringDefault(body, "admin", "user_id"),
		Username: firstStringDefault(body, "admin", "username"),
		Password: firstStringDefault(body, "admin", "password"),
		Email:    firstStringDefault(body, "admin@example.local", "email"),
		Role:     "admin",
		Nickname: firstStringDefault(body, "管理员", "nickname"),
	}
	created, err := s.core.Store.CreateUser(u)
	if err != nil {
		return domain.User{Username: u.Username}, false, err
	}
	return created, true, nil
}

func (s *AccountService) ListUsers() []domain.User {
	return s.core.Store.ListUsers()
}

func (s *AccountService) CreateUser(body map[string]any) (domain.User, error) {
	u := domain.User{
		UserID:   stringValue(body["user_id"]),
		Username: stringValue(body["username"]),
		Nickname: stringValue(body["nickname"]),
		Email:    stringValue(body["email"]),
		Phone:    stringValue(body["phone"]),
		Password: firstStringDefault(body, "ChangeMe123!", "password"),
		Role:     firstStringDefault(body, "user", "role"),
	}
	if strings.TrimSpace(u.Username) == "" {
		return domain.User{}, errors.New("username不能为空")
	}
	return s.core.Store.CreateUser(u)
}

func (s *AccountService) Detail(userID string) (domain.User, bool) {
	return s.core.Store.GetUser(userID)
}

func (s *AccountService) Update(userID string, body map[string]any) (domain.User, bool) {
	return s.core.Store.UpdateUser(userID, body)
}

func (s *AccountService) Delete(userID string) bool {
	return s.core.Store.DeleteUser(userID)
}

func (s *AccountService) UpdatePassword(userID string, body map[string]any) (domain.User, bool, error) {
	password := firstString(body, "new_password", "password")
	if password == "" {
		return domain.User{}, false, errors.New("password不能为空")
	}
	u, ok := s.core.Store.UpdateUser(userID, map[string]any{"password": password})
	return u, ok, nil
}

func tokenFromAuthHeader(authHeader string) string {
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
}

func randomAccessToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}
