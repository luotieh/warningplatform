package bruteforce

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vulnscan-backend/dict"
	"vulnscan-backend/pkg/payload"
	"vulnscan-backend/scan/core"
)

type BruteForcer struct {
	dictStore    *dict.Store
	checkers     map[string]ProtocolChecker
	maxWorkers   int
	lockoutCap   int
	perHostDelay time.Duration
}

type ProtocolChecker interface {
	Name() string
	DefaultPort() int
	MatchService(service string, port int) bool
	NeedsUsername() bool
	Check(ctx context.Context, host string, port int, username, password string) (bool, string)
}

type BruteResult struct {
	Service  string
	Host     string
	Port     int
	Username string
	Password string
	Banner   string
}

func New(dictStore *dict.Store) *BruteForcer {
	bf := &BruteForcer{
		dictStore:    dictStore,
		checkers:     make(map[string]ProtocolChecker),
		maxWorkers:   30,
		lockoutCap:   3,
		perHostDelay: 200 * time.Millisecond,
	}

	for _, chk := range []ProtocolChecker{
		&FTPChecker{}, &SSHChecker{}, &TelnetChecker{},
		&MySQLChecker{}, &PostgresChecker{}, &MSSQLChecker{},
		&RedisChecker{}, &MongoChecker{}, &MemcachedChecker{},
		&SMTPChecker{}, &POP3Checker{}, &IMAPChecker{},
		&SNMPChecker{}, &LDAPChecker{}, &VNCChecker{},
		&RDPChecker{},
	} {
		bf.checkers[chk.Name()] = chk
	}

	return bf
}

func (m *BruteForcer) ID() string       { return "brute_force" }
func (m *BruteForcer) Name() string     { return "密码爆破" }
func (m *BruteForcer) Category() string { return "vuln" }

func (m *BruteForcer) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	start := time.Now()
	result := &core.ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex

	maxWorkers := m.maxWorkers
	if v, ok := config["max_workers"].(float64); ok && v > 0 {
		maxWorkers = int(v)
	}
	lockoutCap := m.lockoutCap
	if v, ok := config["lockout_cap"].(float64); ok && v > 0 {
		lockoutCap = int(v)
	}

	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, t := range targets {
		if t.Port <= 0 {
			continue
		}

		checkers := m.matchCheckers(t)
		if len(checkers) == 0 {
			continue
		}

		host := t.Host
		if t.IP != "" {
			host = t.IP
		}

		for _, chk := range checkers {
			select {
			case <-ctx.Done():
				wg.Wait()
				result.Duration = time.Since(start)
				return result, ctx.Err()
			default:
			}

			usernames, passwords := m.loadCredentials(chk, config)
			if !chk.NeedsUsername() {
				usernames = []string{""}
			}

			var failCount int32

			for _, u := range usernames {
				for _, p := range passwords {
					if atomic.LoadInt32(&failCount) >= int32(lockoutCap)*int32(len(usernames)) {
						break
					}

					select {
					case <-ctx.Done():
						wg.Wait()
						result.Duration = time.Since(start)
						return result, ctx.Err()
					default:
					}

					wg.Add(1)
					sem <- struct{}{}
					go func(checker ProtocolChecker, target *core.Target, h string, port int, user, pass string) {
						defer wg.Done()
						defer func() { <-sem }()

						ok, banner := checker.Check(ctx, h, port, user, pass)
						if !ok {
							atomic.AddInt32(&failCount, 1)
							return
						}

						severity := "critical"
						if pass == "" || pass == user {
							severity = "critical"
						}

						desc := fmt.Sprintf("服务 %s 存在弱口令", checker.Name())
						if user != "" || pass != "" {
							pwdLabel := pass
							if pwdLabel == "" {
								pwdLabel = "(空)"
							}
							desc += fmt.Sprintf(" %s/%s", user, pwdLabel)
						}

						data := map[string]string{
							"service":  checker.Name(),
							"username": user,
							"password": pass,
							"protocol": target.Protocol,
						}
						if banner != "" {
							data["banner"] = truncate(banner, 200)
						}

						finding := &core.Finding{
							ModuleID:         m.ID(),
							Target:           target,
							Type:             "weak_password",
							Title:            fmt.Sprintf("弱口令 - %s %s:%d", checker.Name(), h, port),
							Description:      desc,
							Severity:         severity,
							Confidence:       98,
							ConfidenceReason: "密码登录验证成功",
							Evidence:         fmt.Sprintf("成功认证 %s@%s:%d (服务: %s)", user, h, port, checker.Name()),
							Timestamp:        time.Now(),
							Data:             data,
						}

						mu.Lock()
						result.Findings = append(result.Findings, finding)
						mu.Unlock()

						slog.Warn("[!] 发现弱口令", "service", checker.Name(), "host", h, "port", port, "user", user)
					}(chk, t, host, t.Port, u, p)

					time.Sleep(m.perHostDelay)
				}
			}
		}
	}

	wg.Wait()
	result.Duration = time.Since(start)

	slog.Info("[+] 密码爆破完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *BruteForcer) matchCheckers(t *core.Target) []ProtocolChecker {
	var matched []ProtocolChecker
	svc := targetServiceForMatch(t)

	for _, chk := range m.checkers {
		if chk.MatchService(svc, t.Port) {
			matched = append(matched, chk)
		}
	}
	return matched
}

func targetServiceForMatch(t *core.Target) string {
	if t == nil {
		return ""
	}
	if s := strings.TrimSpace(t.Service); s != "" {
		return strings.ToLower(s)
	}
	if s := strings.TrimSpace(t.Protocol); s != "" {
		lower := strings.ToLower(s)
		if lower != "tcp" && lower != "udp" {
			return lower
		}
	}
	if t.Extra != nil {
		if s := strings.TrimSpace(t.Extra["service"]); s != "" {
			return strings.ToLower(s)
		}
	}
	return ""
}

func (m *BruteForcer) loadCredentials(chk ProtocolChecker, config map[string]interface{}) (usernames, passwords []string) {
	if m.dictStore != nil {
		usernames = m.dictStore.GetUsernames()
		passwords = m.dictStore.GetPasswords()
	}

	if len(usernames) == 0 {
		payload.LogFallbackOnce("bruteforce")
		usernames = payload.MinimalUsernamesForService(chk.Name())
	}
	if len(passwords) == 0 {
		payload.LogFallbackOnce("bruteforce")
		passwords = payload.MinimalPasswords()
	}

	if cu, ok := config["usernames"].([]interface{}); ok {
		for _, u := range cu {
			if s, ok := u.(string); ok {
				usernames = append(usernames, s)
			}
		}
	}
	if cp, ok := config["passwords"].([]interface{}); ok {
		for _, p := range cp {
			if s, ok := p.(string); ok {
				passwords = append(passwords, s)
			}
		}
	}

	return dedup(usernames), dedup(passwords)
}

func dedup(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	var out []string
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
