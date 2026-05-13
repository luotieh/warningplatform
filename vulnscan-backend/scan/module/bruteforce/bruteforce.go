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
						if user != "" {
							desc += fmt.Sprintf(" [用户: %s]", user)
						}

						data := map[string]string{
							"service":  checker.Name(),
							"username": user,
							"password": maskPassword(pass),
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
	svc := strings.ToLower(t.Protocol)
	if extra, ok := t.Extra["service"]; ok {
		svc = strings.ToLower(extra)
	}

	for _, chk := range m.checkers {
		if chk.MatchService(svc, t.Port) {
			matched = append(matched, chk)
		}
	}
	return matched
}

func (m *BruteForcer) loadCredentials(chk ProtocolChecker, config map[string]interface{}) (usernames, passwords []string) {
	if m.dictStore != nil {
		usernames = m.dictStore.GetUsernames()
		passwords = m.dictStore.GetPasswords()
	}

	if len(usernames) == 0 {
		usernames = defaultUsernamesForService(chk.Name())
	}
	if len(passwords) == 0 {
		passwords = defaultPasswords()
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

func defaultUsernamesForService(service string) []string {
	m := map[string][]string{
		"FTP":        {"ftp", "anonymous", "admin", "root", "www", "web"},
		"SSH":        {"root", "admin", "ubuntu", "centos", "ec2-user", "deploy", "git"},
		"Telnet":     {"root", "admin", "user", "guest"},
		"MySQL":      {"root", "admin", "mysql", "dba", "test"},
		"PostgreSQL": {"postgres", "admin", "pgsql", "dbuser"},
		"MSSQL":      {"sa", "admin", "mssql"},
		"Redis":      {},
		"MongoDB":    {"admin", "root", "mongodb"},
		"Memcached":  {},
		"SMTP":       {"admin", "postmaster", "info", "test"},
		"POP3":       {"admin", "user", "test"},
		"IMAP":       {"admin", "user", "test"},
		"SNMP":       {},
		"LDAP":       {"cn=admin", "cn=Manager", "cn=root", "admin"},
		"VNC":        {},
		"RDP":        {"administrator", "admin", "user", "guest"},
	}
	if users, ok := m[service]; ok && len(users) > 0 {
		return users
	}
	return []string{"admin", "root"}
}

func defaultPasswords() []string {
	return []string{
		"", "admin", "admin123", "admin@123", "admin888",
		"123456", "12345678", "123456789",
		"password", "P@ssw0rd", "passw0rd",
		"root", "root123", "root@123",
		"test", "test123", "guest",
		"default", "changeme", "letmein",
		"qwerty", "abc123", "111111", "000000",
		"1qaz2wsx", "1q2w3e4r",
		"Aa123456", "Qwer1234",
	}
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

func maskPassword(pwd string) string {
	if pwd == "" {
		return "(空)"
	}
	if len(pwd) <= 2 {
		return "***"
	}
	return string(pwd[0]) + strings.Repeat("*", len(pwd)-2) + string(pwd[len(pwd)-1])
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
