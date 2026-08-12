// Package authlocal 提供 warning-platform 独立运行时的本地认证能力：
// 本地用户表 + HMAC 令牌，兼容前端 /api/iam/* 登录协议，剥离远程 IAM 依赖。
package authlocal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vulnscan-backend/boot"

	"code.yt-security.com/public/access/auth"
	authMiddleware "code.yt-security.com/public/access/auth/middleware"
	sdkMiddleware "code.yt-security.com/public/access/middleware"
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	ctxUserID   = "local_auth_user_id"
	ctxUsername = "local_auth_username"
	ctxRole     = "local_auth_role"

	defaultAdminUser     = "admin"
	defaultAdminPassword = "admin"
)

// LocalUser 本地登录账户（独立运行模式）。
type LocalUser struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       string    `gorm:"size:64;uniqueIndex" json:"user_id"`
	Username     string    `gorm:"size:64;uniqueIndex" json:"username"`
	PasswordHash string    `gorm:"size:128" json:"-"`
	Salt         string    `gorm:"size:64" json:"-"`
	Nickname     string    `gorm:"size:128" json:"nickname"`
	Email        string    `gorm:"size:128" json:"email"`
	Phone        string    `gorm:"size:64" json:"phone"`
	Role         string    `gorm:"size:32;default:admin" json:"role"`
	Status       int       `gorm:"default:1" json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// MenuNode 本地模式菜单节点（兼容前端 IAM VisibleMenu 结构）。
type MenuNode struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Title     string     `json:"title"`
	Path      string     `json:"path"`
	Component string     `json:"component,omitempty"`
	Icon      string     `json:"icon,omitempty"`
	MenuType  int        `json:"menu_type"`
	Sort      int        `json:"sort"`
	Children  []MenuNode `json:"children,omitempty"`
}

type menuGroup struct {
	AppID   string     `json:"app_id"`
	AppName string     `json:"app_name"`
	Menus   []MenuNode `json:"menus"`
}

type tokenClaims struct {
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Role string `json:"role"`
	Typ  string `json:"typ"` // access / refresh
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// Service 本地认证服务。
type Service struct {
	gdb           *gorm.DB
	secret        []byte
	adminPassword string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	menus         []menuGroup
}

// New 创建本地认证服务；secret 取自 [sso].cookie_secret（缺失时生成随机密钥并持久到配置）。
func New(gdb *gorm.DB, cfg *boot.Config) *Service {
	secret := []byte(strings.TrimSpace(cfg.SSO.CookieSecret))
	if len(secret) == 0 {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		secret = []byte(hex.EncodeToString(buf))
	}
	s := &Service{
		gdb:           gdb,
		secret:        secret,
		adminPassword: strings.TrimSpace(cfg.IAM.LocalAdminPassword),
		accessTTL:     24 * time.Hour,
		refreshTTL:    7 * 24 * time.Hour,
		menus:         defaultMenus(),
	}
	if s.adminPassword == "" {
		s.adminPassword = defaultAdminPassword
	}
	return s
}

// Ensure 建表并初始化默认管理员账户。
func (s *Service) Ensure() error {
	if err := s.gdb.AutoMigrate(&LocalUser{}); err != nil {
		return fmt.Errorf("local auth migrate: %w", err)
	}
	var count int64
	if err := s.gdb.Model(&LocalUser{}).Where("username = ?", defaultAdminUser).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	salt := randomHex(16)
	user := LocalUser{
		UserID:       "u-" + randomHex(8),
		Username:     defaultAdminUser,
		PasswordHash: hashPassword(s.adminPassword, salt),
		Salt:         salt,
		Nickname:     "管理员",
		Email:        "admin@example.local",
		Role:         "admin",
		Status:       1,
	}
	return s.gdb.Create(&user).Error
}

// RegisterRoutes 注册兼容前端的 /api/iam/* 路由。
func (s *Service) RegisterRoutes(g *gin.RouterGroup) {
	r := g.Group("/iam")
	r.POST("/auth/login", s.Login)
	r.POST("/auth/refresh", s.Refresh)
	r.POST("/auth/logout", s.Logout)
	r.GET("/auth/login-settings", s.LoginSettings)
	auth := r.Group("", s.Middleware())
	auth.GET("/profile", s.Profile)
	auth.GET("/me", s.Profile)
	auth.GET("/menus", s.Menus)
	auth.GET("/routes", s.Menus)
	auth.GET("/access-codes", s.AccessCodes)
	// IAM 轮询/公共接口（本地模式返回空数据 JSON，避免前端定时轮询
	// 打到 SPA 返回 HTML 导致解析失败弹「内部服务器错误」）。
	r.GET("/notifications/unread/count", s.NotificationUnreadCount)
	r.GET("/notifications", s.Notifications)
	r.GET("/notifications/:id", s.NotificationDetail)
	r.DELETE("/notifications/:id", s.NotificationDelete)
	r.POST("/notifications/read", s.NotificationRead)
	r.GET("/todos/stats", s.TodosStats)
	r.GET("/todos", s.Todos)
	r.GET("/config/public", s.PublicConfig)
}

// Middleware 校验 Bearer 令牌并注入用户上下文。
func (s *Service) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := bearerToken(c.GetHeader("Authorization"))
		if token == "" {
			unauthorized(c, "未登录或登录已过期")
			return
		}
		claims, err := s.parseToken(token, "access")
		if err != nil {
			unauthorized(c, "登录凭证无效或已过期")
			return
		}
		c.Set(ctxUserID, claims.Sub)
		c.Set(ctxUsername, claims.Name)
		c.Set(ctxRole, claims.Role)
		// 同步写入 SDK 用户上下文（auth/middleware + middleware 两个 key），
		// 避免 dispatch/formdesign/incident 等通过 iamsdk.GetCurrentUser /
		// middleware.GetCurrentUser 取用户时拿到 nil 而空指针 panic。
		authMiddleware.SetCurrentUser(c, &auth.UserClaims{
			UserID:       claims.Sub,
			Account:      claims.Name,
			Roles:        []string{claims.Role},
			IsPrivileged: true,
		})
		sdkMiddleware.SetCurrentUser(c, &sdkMiddleware.CurrentUser{
			UserID:       claims.Sub,
			Account:      claims.Name,
			Roles:        []string{claims.Role},
			IsPrivileged: true,
		})
		c.Next()
	}
}

// Authorize 本地授权：仅 admin 角色放行（当前种子账户均为 admin）。
func (s *Service) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		if role := c.GetString(ctxRole); role != "admin" {
			web.Fail(c).HTTP(http.StatusForbidden).Msg("无权限访问").Send()
			c.Abort()
			return
		}
		c.Next()
	}
}

// Login 本地账户登录（兼容前端 POST /api/iam/auth/login，body 使用 account/username）。
func (s *Service) Login(c *gin.Context) {
	var body struct {
		Account  string `json:"account"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		web.Fail(c).HTTP(http.StatusBadRequest).Msg("请求参数错误").Send()
		return
	}
	username := strings.TrimSpace(body.Account)
	if username == "" {
		username = strings.TrimSpace(body.Username)
	}
	if username == "" || body.Password == "" {
		web.Fail(c).HTTP(http.StatusBadRequest).Msg("请输入账号和密码").Send()
		return
	}
	var user LocalUser
	if err := s.gdb.Where("username = ?", username).First(&user).Error; err != nil {
		web.Fail(c).HTTP(http.StatusUnauthorized).Msg("账号或密码错误").Send()
		return
	}
	if user.Status != 1 || hashPassword(body.Password, user.Salt) != user.PasswordHash {
		web.Fail(c).HTTP(http.StatusUnauthorized).Msg("账号或密码错误").Send()
		return
	}
	now := time.Now().Unix()
	access, err := s.issueToken(user, "access", now, now+int64(s.accessTTL.Seconds()))
	if err != nil {
		web.Fail(c).HTTP(http.StatusInternalServerError).Msg("签发令牌失败").Send()
		return
	}
	refresh, err := s.issueToken(user, "refresh", now, now+int64(s.refreshTTL.Seconds()))
	if err != nil {
		web.Fail(c).HTTP(http.StatusInternalServerError).Msg("签发令牌失败").Send()
		return
	}
	web.Succeed(c).Data(loginResult(user, access, refresh, now)).Send()
}

// Refresh 刷新令牌。
func (s *Service) Refresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		web.Fail(c).HTTP(http.StatusBadRequest).Msg("请求参数错误").Send()
		return
	}
	claims, err := s.parseToken(strings.TrimSpace(body.RefreshToken), "refresh")
	if err != nil {
		unauthorized(c, "刷新凭证无效或已过期")
		return
	}
	var user LocalUser
	if err := s.gdb.Where("user_id = ?", claims.Sub).First(&user).Error; err != nil {
		unauthorized(c, "账户不存在")
		return
	}
	now := time.Now().Unix()
	access, err := s.issueToken(user, "access", now, now+int64(s.accessTTL.Seconds()))
	if err != nil {
		web.Fail(c).HTTP(http.StatusInternalServerError).Msg("签发令牌失败").Send()
		return
	}
	refresh, err := s.issueToken(user, "refresh", now, now+int64(s.refreshTTL.Seconds()))
	if err != nil {
		web.Fail(c).HTTP(http.StatusInternalServerError).Msg("签发令牌失败").Send()
		return
	}
	web.Succeed(c).Data(refreshResult(user, access, refresh, now)).Send()
}

// Logout 本地登出（无服务端状态，直接成功）。
func (s *Service) Logout(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"logout": true}).Send()
}

// LoginSettings 返回登录页配置（关闭验证码/SSO）。
func (s *Service) LoginSettings(c *gin.Context) {
	web.Succeed(c).Data(gin.H{
		"captcha_enabled": false,
		"sso_enabled":     false,
		"allow_totp":      false,
		"login_method":    "local",
	}).Send()
}

// Profile 返回当前用户信息与角色（兼容前端 /iam/profile、/iam/me）。
func (s *Service) Profile(c *gin.Context) {
	userID := c.GetString(ctxUserID)
	var user LocalUser
	if err := s.gdb.Where("user_id = ?", userID).First(&user).Error; err != nil {
		unauthorized(c, "账户不存在")
		return
	}
	web.Succeed(c).Data(permissionBundle(user)).Send()
}

// Menus 返回静态菜单（兼容前端 /iam/menus、/iam/routes）。
func (s *Service) Menus(c *gin.Context) {
	web.Succeed(c).Data(s.menus).Send()
}

// AccessCodes 返回权限码（本地模式返回空，前端按后端权限模式处理）。
func (s *Service) AccessCodes(c *gin.Context) {
	web.Succeed(c).Data([]string{}).Send()
}

// ListUsers 返回本地账户列表（兼容 /api/system/users）。
func (s *Service) ListUsers(c *gin.Context) {
	var users []LocalUser
	if err := s.gdb.Order("id ASC").Find(&users).Error; err != nil {
		web.Fail(c).Msg("查询本地账户失败").Send()
		return
	}
	items := make([]gin.H, 0, len(users))
	for _, u := range users {
		items = append(items, gin.H{
			"user_id":     u.UserID,
			"account":     u.Username,
			"name":        u.Nickname,
			"email":       u.Email,
			"phone":       u.Phone,
			"organize_id": "",
		})
	}
	web.Succeed(c).List(int64(len(items)), items).Send()
}

// NotificationUnreadCount 未读通知数（本地模式恒为 0）。
func (s *Service) NotificationUnreadCount(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"count": 0, "total": 0}).Send()
}

// Notifications 通知列表（本地模式返回空分页）。
func (s *Service) Notifications(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"items": []any{}, "total": 0}).Send()
}

// NotificationDetail 通知详情（本地模式无数据）。
func (s *Service) NotificationDetail(c *gin.Context) {
	web.Succeed(c).Data(gin.H{}).Send()
}

// NotificationDelete 删除通知（本地模式直接成功）。
func (s *Service) NotificationDelete(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"deleted": true}).Send()
}

// NotificationRead 标记已读（本地模式直接成功）。
func (s *Service) NotificationRead(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"ok": true}).Send()
}

// Todos 待办列表（本地模式返回空）。
func (s *Service) Todos(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"items": []any{}, "total": 0}).Send()
}

// TodosStats 待办统计（本地模式全 0）。
func (s *Service) TodosStats(c *gin.Context) {
	web.Succeed(c).Data(gin.H{"total": 0, "pending": 0, "done": 0}).Send()
}

// PublicConfig 公共配置（本地模式返回空对象）。
func (s *Service) PublicConfig(c *gin.Context) {
	web.Succeed(c).Data(gin.H{}).Send()
}

// --- 内部实现 ---

func (s *Service) issueToken(user LocalUser, typ string, iat, exp int64) (string, error) {
	payload, err := json.Marshal(tokenClaims{
		Sub:  user.UserID,
		Name: user.Username,
		Role: user.Role,
		Typ:  typ,
		Iat:  iat,
		Exp:  exp,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(enc))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return enc + "." + sig, nil
}

func (s *Service) parseToken(token, typ string) (*tokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(parts[0]))
	want, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(want, mac.Sum(nil)) {
		return nil, errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var claims tokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	if claims.Typ != typ || time.Now().Unix() >= claims.Exp {
		return nil, errors.New("token expired or wrong type")
	}
	return &claims, nil
}

func hashPassword(password, salt string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func unauthorized(c *gin.Context, msg string) {
	web.Fail(c).HTTP(http.StatusUnauthorized).Msg(msg).Send()
	c.Abort()
}

func loginResult(user LocalUser, access, refresh string, now int64) gin.H {
	return gin.H{
		"session":             access,
		"access_token":        access,
		"refresh_token":       refresh,
		"token_type":          "Bearer",
		"expires_at":          now + int64((24 * time.Hour).Seconds()),
		"refresh_expires_at":  now + int64((7 * 24 * time.Hour).Seconds()),
		"user_id":             user.UserID,
		"account":             user.Username,
		"issued_at":           now,
		"require_totp":        false,
		"allow_totp":          false,
		"login_method":        "local",
		"locked_until":        0,
		"password_expired":    false,
		"invalid_credentials": false,
	}
}

func refreshResult(user LocalUser, access, refresh string, now int64) gin.H {
	return gin.H{
		"access_token":       access,
		"refresh_token":      refresh,
		"token_type":         "Bearer",
		"expires_at":         now + int64((24 * time.Hour).Seconds()),
		"refresh_expires_at": now + int64((7 * 24 * time.Hour).Seconds()),
		"user_id":            user.UserID,
		"account":            user.Username,
		"issued_at":          now,
	}
}

func permissionBundle(user LocalUser) gin.H {
	return gin.H{
		"user": gin.H{
			"user_id":               user.UserID,
			"user_name":             user.Username,
			"nick_name":             user.Nickname,
			"avatar":                "",
			"email":                 user.Email,
			"phone":                 user.Phone,
			"status":                user.Status,
			"mfa":                   0,
			"primary_organize_id":   "",
			"primary_department_id": "",
		},
		"roles":        []gin.H{{"id": user.Role, "name": "管理员", "code": user.Role, "description": "本地认证管理员"}},
		"applications": []gin.H{{"id": "warning-platform", "app_name": "告警平台", "display_name": "告警平台"}},
		"organizes":    []gin.H{},
		"departments":  []gin.H{},
		"positions":    []gin.H{},
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func defaultMenus() []menuGroup {
	return []menuGroup{{
		AppID:   "warning-platform",
		AppName: "告警平台",
		Menus: []MenuNode{
			{ID: "workbench", Name: "workbench", Title: "工作台", Path: "/workbench/overview", MenuType: 1, Sort: 1},
			{ID: "incident", Name: "incident", Title: "安全事件", Path: "/incident/list", MenuType: 1, Sort: 10},
			{ID: "vuln", Name: "vuln", Title: "漏洞管理", Path: "/vuln/list", MenuType: 1, Sort: 20},
			{ID: "monitor", Name: "monitor", Title: "网站监测", Path: "/monitor/center", MenuType: 1, Sort: 30},
			{ID: "traffic", Name: "traffic-analysis", Title: "流量分析", Path: "/traffic-analysis", MenuType: 1, Sort: 40, Children: []MenuNode{
				{ID: "ly-overview", Name: "ly-overview", Title: "总览", Path: "/ly/overview", MenuType: 1, Sort: 1},
				{ID: "ly-event", Name: "ly-event", Title: "事件列表", Path: "/ly/event/list", MenuType: 1, Sort: 2},
				{ID: "ly-assets", Name: "ly-assets", Title: "资产管理", Path: "/ly/assets", MenuType: 1, Sort: 3},
				{ID: "ly-config", Name: "ly-config", Title: "配置", Path: "/ly/config", MenuType: 1, Sort: 4},
			}},
			{ID: "system", Name: "system", Title: "系统设置", Path: "/system/settings", MenuType: 1, Sort: 90},
			{ID: "cluster", Name: "cluster", Title: "节点管理", Path: "/cluster/nodes", MenuType: 1, Sort: 95},
			{ID: "dispatch", Name: "dispatch", Title: "派发中心", Path: "/dispatch/board", MenuType: 1, Sort: 96},
		},
	}}
}
