package scanhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AuthType enumerates supported authentication methods.
type AuthType string

const (
	AuthNone     AuthType = "none"
	AuthFormPost AuthType = "form_post"
	AuthJSONPost AuthType = "json_post"
	AuthBasic    AuthType = "basic"
	AuthBearer   AuthType = "bearer"
	AuthCookie   AuthType = "cookie"
	AuthCustom   AuthType = "custom"
)

// AuthConfig describes how to authenticate against a target application.
type AuthConfig struct {
	Type            AuthType          `json:"type"`
	LoginURL        string            `json:"login_url"`
	Username        string            `json:"username"`
	Password        string            `json:"password"`
	UsernameField   string            `json:"username_field"`
	PasswordField   string            `json:"password_field"`
	ExtraFields     map[string]string `json:"extra_fields,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         string            `json:"cookies,omitempty"`
	BearerToken     string            `json:"bearer_token,omitempty"`
	SuccessPattern  string            `json:"success_pattern,omitempty"`
	FailurePattern  string            `json:"failure_pattern,omitempty"`
	LogoutPattern   string            `json:"logout_pattern,omitempty"`
	TokenExtractRe  string            `json:"token_extract_re,omitempty"`
	TokenHeaderName string            `json:"token_header_name,omitempty"`
	KeepAliveURL    string            `json:"keep_alive_url,omitempty"`
	KeepAliveSec    int               `json:"keep_alive_sec,omitempty"`
}

// AuthSession manages an authenticated session with automatic keep-alive.
type AuthSession struct {
	mu            sync.RWMutex
	config        AuthConfig
	cookies       []*http.Cookie
	authHeaders   map[string]string
	bearerToken   string
	authenticated bool
	lastRefresh   time.Time
	loginCount    int
	jar           *cookiejar.Jar
	stopped       chan struct{}
}

// NewAuthSession creates an AuthSession from configuration and attempts login.
func NewAuthSession(config AuthConfig) (*AuthSession, error) {
	jar, _ := cookiejar.New(nil)
	as := &AuthSession{
		config:      config,
		authHeaders: make(map[string]string),
		jar:         jar,
		stopped:     make(chan struct{}),
	}

	if config.Type == AuthNone {
		as.authenticated = true
		return as, nil
	}

	if config.Type == AuthBearer && config.BearerToken != "" {
		as.bearerToken = config.BearerToken
		as.authHeaders["Authorization"] = "Bearer " + config.BearerToken
		as.authenticated = true
		return as, nil
	}

	if config.Type == AuthCookie && config.Cookies != "" {
		as.cookies = parseCookieString(config.Cookies)
		as.authenticated = true
		return as, nil
	}

	if config.Type == AuthBasic {
		as.authenticated = true
		return as, nil
	}

	if config.Headers != nil {
		for k, v := range config.Headers {
			as.authHeaders[k] = v
		}
		if config.Type == AuthCustom {
			as.authenticated = true
			return as, nil
		}
	}

	if err := as.login(); err != nil {
		return nil, fmt.Errorf("认证登录失败: %w", err)
	}

	if config.KeepAliveSec > 0 {
		go as.keepAliveLoop()
	}

	return as, nil
}

func (as *AuthSession) login() error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.loginCount++

	switch as.config.Type {
	case AuthFormPost:
		return as.doFormLogin()
	case AuthJSONPost:
		return as.doJSONLogin()
	default:
		return fmt.Errorf("不支持的认证类型: %s", as.config.Type)
	}
}

func (as *AuthSession) doFormLogin() error {
	usernameField := as.config.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := as.config.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}

	formData := url.Values{}
	formData.Set(usernameField, as.config.Username)
	formData.Set(passwordField, as.config.Password)
	for k, v := range as.config.ExtraFields {
		formData.Set(k, v)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     as.jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("POST", as.config.LoginURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("登录请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	if err := as.validateLoginResponse(resp, string(body)); err != nil {
		return err
	}

	as.extractSessionData(resp, string(body))
	as.authenticated = true
	as.lastRefresh = time.Now()

	slog.Info("[AuthSession] 表单登录成功",
		"url", as.config.LoginURL,
		"cookies_count", len(as.cookies),
		"attempt", as.loginCount)

	return nil
}

func (as *AuthSession) doJSONLogin() error {
	usernameField := as.config.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := as.config.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}

	payload := map[string]string{
		usernameField: as.config.Username,
		passwordField: as.config.Password,
	}
	for k, v := range as.config.ExtraFields {
		payload[k] = v
	}

	jsonBody, _ := json.Marshal(payload)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     as.jar,
	}

	req, err := http.NewRequest("POST", as.config.LoginURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("JSON 登录请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	if err := as.validateLoginResponse(resp, string(body)); err != nil {
		return err
	}

	as.extractSessionData(resp, string(body))
	as.authenticated = true
	as.lastRefresh = time.Now()

	slog.Info("[AuthSession] JSON 登录成功",
		"url", as.config.LoginURL,
		"attempt", as.loginCount)

	return nil
}

func (as *AuthSession) validateLoginResponse(resp *http.Response, body string) error {
	if as.config.FailurePattern != "" {
		re, err := regexp.Compile(as.config.FailurePattern)
		if err == nil && re.MatchString(body) {
			return fmt.Errorf("登录失败：响应匹配失败模式 '%s'", as.config.FailurePattern)
		}
	}

	if as.config.SuccessPattern != "" {
		re, err := regexp.Compile(as.config.SuccessPattern)
		if err == nil {
			if !re.MatchString(body) {
				return fmt.Errorf("登录失败：响应未匹配成功模式 '%s'", as.config.SuccessPattern)
			}
		}
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("登录失败：HTTP %d", resp.StatusCode)
	}

	return nil
}

func (as *AuthSession) extractSessionData(resp *http.Response, body string) {
	loginURL, _ := url.Parse(as.config.LoginURL)
	if loginURL != nil {
		as.cookies = as.jar.Cookies(loginURL)
	}

	for _, c := range resp.Cookies() {
		found := false
		for i, existing := range as.cookies {
			if existing.Name == c.Name {
				as.cookies[i] = c
				found = true
				break
			}
		}
		if !found {
			as.cookies = append(as.cookies, c)
		}
	}

	if as.config.TokenExtractRe != "" {
		re, err := regexp.Compile(as.config.TokenExtractRe)
		if err == nil {
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				token := matches[1]
				headerName := as.config.TokenHeaderName
				if headerName == "" {
					headerName = "Authorization"
					token = "Bearer " + token
				}
				as.authHeaders[headerName] = token
				as.bearerToken = matches[1]
				slog.Info("[AuthSession] 从响应中提取了令牌", "header", headerName)
			}
		}
	}
}

func (as *AuthSession) keepAliveLoop() {
	interval := time.Duration(as.config.KeepAliveSec) * time.Second
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-as.stopped:
			return
		case <-ticker.C:
			as.doKeepAlive()
		}
	}
}

func (as *AuthSession) doKeepAlive() {
	keepAliveURL := as.config.KeepAliveURL
	if keepAliveURL == "" {
		keepAliveURL = as.config.LoginURL
	}

	req, err := http.NewRequest("GET", keepAliveURL, nil)
	if err != nil {
		return
	}

	as.ApplyTo(req)

	client := &http.Client{Timeout: 15 * time.Second, Jar: as.jar}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("[AuthSession] Keep-alive 请求失败, 尝试重新登录", "error", err)
		_ = as.login()
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if as.config.LogoutPattern != "" {
		re, _ := regexp.Compile(as.config.LogoutPattern)
		if re != nil && re.MatchString(string(body)) {
			slog.Warn("[AuthSession] 会话已过期（匹配登出模式），重新登录")
			_ = as.login()
			return
		}
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		slog.Warn("[AuthSession] 会话已过期（HTTP状态码），重新登录", "status", resp.StatusCode)
		_ = as.login()
		return
	}

	as.mu.Lock()
	as.lastRefresh = time.Now()
	loginURL, _ := url.Parse(as.config.LoginURL)
	if loginURL != nil {
		as.cookies = as.jar.Cookies(loginURL)
	}
	as.mu.Unlock()

	slog.Debug("[AuthSession] Keep-alive 成功", "url", keepAliveURL)
}

// ApplyTo injects auth credentials into an HTTP request.
func (as *AuthSession) ApplyTo(req *http.Request) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	if as.config.Type == AuthBasic {
		req.SetBasicAuth(as.config.Username, as.config.Password)
		return
	}

	for _, c := range as.cookies {
		req.AddCookie(c)
	}
	for k, v := range as.authHeaders {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
}

// GetClientOptions returns ClientOptions for creating an authenticated ScanHTTPClient.
func (as *AuthSession) GetClientOptions() []ClientOption {
	as.mu.RLock()
	defer as.mu.RUnlock()

	var opts []ClientOption
	if len(as.authHeaders) > 0 {
		headersCopy := make(map[string]string, len(as.authHeaders))
		for k, v := range as.authHeaders {
			headersCopy[k] = v
		}
		opts = append(opts, WithAuthHeaders(headersCopy))
	}
	if len(as.cookies) > 0 {
		cookiesCopy := make([]*http.Cookie, len(as.cookies))
		copy(cookiesCopy, as.cookies)
		opts = append(opts, WithAuthCookies(cookiesCopy))
	}
	return opts
}

// IsAuthenticated returns whether the session is currently authenticated.
func (as *AuthSession) IsAuthenticated() bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.authenticated
}

// Stop terminates the keep-alive loop.
func (as *AuthSession) Stop() {
	select {
	case <-as.stopped:
	default:
		close(as.stopped)
	}
}

func parseCookieString(cookieStr string) []*http.Cookie {
	var cookies []*http.Cookie
	for _, part := range strings.Split(cookieStr, ";") {
		part = strings.TrimSpace(part)
		if idx := strings.IndexByte(part, '='); idx > 0 {
			cookies = append(cookies, &http.Cookie{
				Name:  strings.TrimSpace(part[:idx]),
				Value: strings.TrimSpace(part[idx+1:]),
			})
		}
	}
	return cookies
}

// ParseAuthConfig extracts AuthConfig from a task's parameters map.
func ParseAuthConfig(params map[string]interface{}) *AuthConfig {
	authRaw, ok := params["auth"]
	if !ok {
		return nil
	}
	authMap, ok := authRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	cfg := &AuthConfig{
		Type:            AuthType(getStr(authMap, "type")),
		LoginURL:        getStr(authMap, "login_url"),
		Username:        getStr(authMap, "username"),
		Password:        getStr(authMap, "password"),
		UsernameField:   getStr(authMap, "username_field"),
		PasswordField:   getStr(authMap, "password_field"),
		Cookies:         getStr(authMap, "cookies"),
		BearerToken:     getStr(authMap, "bearer_token"),
		SuccessPattern:  getStr(authMap, "success_pattern"),
		FailurePattern:  getStr(authMap, "failure_pattern"),
		LogoutPattern:   getStr(authMap, "logout_pattern"),
		TokenExtractRe:  getStr(authMap, "token_extract_re"),
		TokenHeaderName: getStr(authMap, "token_header_name"),
		KeepAliveURL:    getStr(authMap, "keep_alive_url"),
	}

	if extra, ok := authMap["extra_fields"].(map[string]interface{}); ok {
		cfg.ExtraFields = make(map[string]string, len(extra))
		for k, v := range extra {
			if s, ok := v.(string); ok {
				cfg.ExtraFields[k] = s
			}
		}
	}
	if headers, ok := authMap["headers"].(map[string]interface{}); ok {
		cfg.Headers = make(map[string]string, len(headers))
		for k, v := range headers {
			if s, ok := v.(string); ok {
				cfg.Headers[k] = s
			}
		}
	}
	if sec, ok := authMap["keep_alive_sec"].(float64); ok {
		cfg.KeepAliveSec = int(sec)
	}

	if cfg.Type == "" {
		return nil
	}

	return cfg
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
