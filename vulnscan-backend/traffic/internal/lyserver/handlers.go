package lyserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// isDuplicateKeyErr 判断 MySQL 唯一键冲突（错误码 1062）。
func isDuplicateKeyErr(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}

type Service struct {
	db *sql.DB
}

func New(db *sql.DB) *Service {
	if db == nil {
		return &Service{}
	}
	return &Service{db: db}
}

func (s *Service) Enabled() bool { return s != nil && s.db != nil }

func (s *Service) Auth(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	params := readParams(r)
	username := firstNonEmpty(params["username"], params["user"], params["name"], "admin")
	password := firstNonEmpty(params["password"], params["passwd"], params["pwd"], "")

	var row struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Password string `json:"-"`
		Role     string `json:"role"`
		Nickname string `json:"nickname"`
	}
	err := s.db.QueryRowContext(r.Context(), `
SELECT id, username, password, role, nickname
FROM t_user WHERE username=? AND enabled=true`, username).
		Scan(&row.ID, &row.Username, &row.Password, &row.Role, &row.Nickname)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	if row.Password != "" && password != "" && row.Password != password {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	token := fmt.Sprintf("ly-%d", time.Now().UTC().UnixNano())
	_, _ = s.db.ExecContext(r.Context(), `
INSERT IGNORE INTO t_user_session (username, token, remote_addr, created_at, expires_at)
VALUES (?,?,?,NOW(6),DATE_ADD(NOW(6), INTERVAL 12 HOUR))`, row.Username, token, r.RemoteAddr)

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"result": "ok",
		"token":  token,
		"data": map[string]any{
			"token": token,
			"user":  map[string]any{"id": row.ID, "username": row.Username, "role": row.Role, "nickname": row.Nickname},
		},
	})
}

func (s *Service) Status(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	agents, err := s.queryRows(r.Context(), `SELECT id, name, ip, port, status, version, created_at, updated_at FROM t_agent ORDER BY id`, []string{"id", "name", "ip", "port", "status", "version", "created_at", "updated_at"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	devices, err := s.queryRows(r.Context(), `SELECT id, name, devid, ip, status, created_at, updated_at FROM t_device ORDER BY id`, []string{"id", "name", "devid", "ip", "status", "created_at", "updated_at"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"result":  "ok",
		"agents":  agents,
		"devices": devices,
		"data": map[string]any{
			"service": "traffic-go-lyserver-compat",
			"status":  "running",
			"agents":  agents,
			"devices": devices,
		},
	})
}

func (s *Service) GetConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	params := readParams(r)
	if strings.EqualFold(params["type"], "agent") {
		s.getAgentConfig(w, r, params)
		return
	}
	key := firstNonEmpty(r.URL.Query().Get("key"), r.URL.Query().Get("name"))
	if key != "" {
		var value []byte
		var desc string
		var updated time.Time
		err := s.db.QueryRowContext(r.Context(), "SELECT value, description, updated_at FROM t_config WHERE `key`=?", key).Scan(&value, &desc, &updated)
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{}})
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{"key": key, "value": jsonValue(value), "description": desc, "updated_at": updated}})
		return
	}
	rows, err := s.db.QueryContext(r.Context(), "SELECT `key`, value, description, updated_at FROM t_config ORDER BY `key`")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var k, desc string
		var v []byte
		var updated time.Time
		if err := rows.Scan(&k, &v, &desc, &updated); err == nil {
			items = append(items, map[string]any{"key": k, "value": jsonValue(v), "description": desc, "updated_at": updated})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": items})
}

func (s *Service) SetConfig(w http.ResponseWriter, r *http.Request) {
	params := readParams(r)
	if strings.EqualFold(params["type"], "agent") && isAgentConnectionTest(params) {
		result := s.testAgentConnection(r.Context(), params)
		if s.Enabled() {
			_ = s.updateNodeStatus(r.Context(), strings.ToLower(firstNonEmpty(params["target"], params["node_type"], "proxy")), params, asString(result["status"]), asString(result["message"]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": result})
		return
	}
	if !s.requireDB(w) {
		return
	}
	if strings.EqualFold(params["type"], "agent") {
		s.setAgentConfig(w, r, params)
		return
	}
	key := firstNonEmpty(params["key"], params["name"], "default")
	desc := firstNonEmpty(params["description"], params["desc"])
	value := params["value"]
	if value == "" {
		b, _ := json.Marshal(params)
		value = string(b)
	}
	if !json.Valid([]byte(value)) {
		b, _ := json.Marshal(value)
		value = string(b)
	}
	_, err := s.db.ExecContext(r.Context(), "INSERT INTO t_config (`key`, value, description, updated_at) VALUES (?,?,?,NOW(6)) ON DUPLICATE KEY UPDATE value=VALUES(value), description=VALUES(description), updated_at=NOW(6)", key, value, desc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{"key": key, "value": jsonValue([]byte(value)), "description": desc}})
}

func (s *Service) GetMO(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	moip := r.URL.Query().Get("moip")
	if moip == "" {
		moip = r.URL.Query().Get("ip")
	}
	query := `SELECT id, moip, moport, protocol, pip, pport, modesc, tag, mogroupid, filter, devid, direction, meta, created_at, updated_at FROM t_mo`
	args := []any{}
	if moip != "" {
		query += ` WHERE moip=?`
		args = append(args, moip)
	}
	query += ` ORDER BY id LIMIT 500`
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, groupID int64
		var ip, port, protocol, pip, pport, desc, tag, filter, devid, direction string
		var meta []byte
		var created, updated time.Time
		if err := rows.Scan(&id, &ip, &port, &protocol, &pip, &pport, &desc, &tag, &groupID, &filter, &devid, &direction, &meta, &created, &updated); err == nil {
			items = append(items, map[string]any{"id": id, "moip": ip, "moport": port, "protocol": protocol, "pip": pip, "pport": pport, "modesc": desc, "tag": tag, "mogroupid": groupID, "filter": filter, "devid": devid, "direction": direction, "meta": jsonValue(meta), "created_at": created, "updated_at": updated})
		}
	}
	data := any(items)
	if moip != "" && len(items) == 1 {
		data = items[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": data, "items": items})
}

func (s *Service) SetMO(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	params := readParams(r)
	moip := firstNonEmpty(params["moip"], params["ip"])
	if moip == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "success",
			"result": "ok",
			"data": map[string]any{
				"noop":    true,
				"message": "moip为空，未修改监控对象",
			},
		})
		return
	}
	moport := firstNonEmpty(params["moport"], params["port"], "0")
	protocol := params["protocol"]
	desc := firstNonEmpty(params["modesc"], params["description"], params["desc"])
	tag := params["tag"]
	filter := firstNonEmpty(params["filter"], "host "+moip)
	devid := firstNonEmpty(params["devid"], "3")
	direction := firstNonEmpty(params["direction"], "ALL")
	meta, _ := json.Marshal(params)

	res, err := s.db.ExecContext(r.Context(), `
INSERT INTO t_mo (moip, moport, protocol, modesc, tag, mogroupid, filter, devid, direction, meta, updated_at)
VALUES (?,?,?,?,?,1,?,?,?,?,NOW(6))
ON DUPLICATE KEY UPDATE
  id=LAST_INSERT_ID(id),
  modesc=VALUES(modesc),
  tag=VALUES(tag),
  filter=VALUES(filter),
  devid=VALUES(devid),
  direction=VALUES(direction),
  meta=VALUES(meta),
  updated_at=NOW(6)`, moip, moport, protocol, desc, tag, filter, devid, direction, string(meta))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{"id": id, "moip": moip, "moport": moport, "protocol": protocol, "modesc": desc}})
}

func (s *Service) GetBWList(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	listType := normalizeListType(firstNonEmpty(r.URL.Query().Get("type"), r.URL.Query().Get("list_type"), r.URL.Query().Get("op")))
	out := map[string]any{"status": "success", "result": "ok"}
	if listType == "black" || listType == "" {
		items, err := s.listBW(r.Context(), "t_blacklist")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out["blacklist"] = items
		if listType == "black" {
			out["data"] = items
		}
	}
	if listType == "white" || listType == "" {
		items, err := s.listBW(r.Context(), "t_whitelist")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out["whitelist"] = items
		if listType == "white" {
			out["data"] = items
		}
	}
	if _, ok := out["data"]; !ok {
		out["data"] = map[string]any{"blacklist": out["blacklist"], "whitelist": out["whitelist"]}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) SetBWList(w http.ResponseWriter, r *http.Request) {
	if !s.requireDB(w) {
		return
	}
	params := readParams(r)
	listType := normalizeListType(firstNonEmpty(params["type"], params["list_type"], "black"))
	table := "t_blacklist"
	if listType == "white" {
		table = "t_whitelist"
	}
	value := firstNonEmpty(params["value"], params["ip"], params["domain"], params["target"])
	if value == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "success",
			"result": "ok",
			"data": map[string]any{
				"noop":    true,
				"message": "value为空，未修改黑白名单",
			},
		})
		return
	}
	op := strings.ToLower(firstNonEmpty(params["op"], params["action"], "add"))
	if op == "del" || op == "delete" || op == "remove" {
		_, err := s.db.ExecContext(r.Context(), fmt.Sprintf(`DELETE FROM %s WHERE value=?`, table), value)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "deleted": value})
		return
	}
	desc := firstNonEmpty(params["description"], params["desc"])
	valueType := firstNonEmpty(params["value_type"], "ip")
	_, err := s.db.ExecContext(r.Context(), fmt.Sprintf(`
INSERT INTO %s (value, value_type, description, enabled, updated_at)
VALUES (?,?,?,true,NOW(6))
ON DUPLICATE KEY UPDATE value_type=VALUES(value_type), description=VALUES(description), enabled=true, updated_at=NOW(6)`, table), value, valueType, desc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{"type": listType, "value": value, "value_type": valueType, "description": desc}})
}

func (s *Service) getAgentConfig(w http.ResponseWriter, r *http.Request, params map[string]string) {
	target := strings.ToLower(firstNonEmpty(params["target"], params["node_type"], "proxy"))
	if target == "device" || target == "collector" {
		items, err := s.queryRows(r.Context(), `
SELECT id, name, devid, ip, status,
       COALESCE(meta->>'$.port', '') AS port,
       COALESCE(meta->>'$.protocol', 'http') AS protocol,
       COALESCE(meta->>'$.comment', '') AS comment,
       COALESCE(meta->>'$.agentid', '') AS agentid,
       COALESCE(meta->>'$.flowtype', '') AS flowtype,
       COALESCE(meta->>'$.interface', '') AS interface,
       COALESCE(meta->>'$.last_test_at', '') AS last_test_at,
       COALESCE(meta->>'$.last_test_message', '') AS last_test_message,
       meta, created_at, updated_at
FROM t_device ORDER BY id`, []string{"id", "name", "devid", "ip", "status", "port", "protocol", "comment", "agentid", "flowtype", "interface", "last_test_at", "last_test_message", "meta", "created_at", "updated_at"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": items, "items": items, "target": "device"})
		return
	}

	items, err := s.queryRows(r.Context(), `
SELECT id, name, ip, port, status, version,
       COALESCE(meta->>'$.protocol', 'http') AS protocol,
       COALESCE(meta->>'$.comment', '') AS comment,
       COALESCE(meta->>'$.last_test_at', '') AS last_test_at,
       COALESCE(meta->>'$.last_test_message', '') AS last_test_message,
       meta, created_at, updated_at
FROM t_agent ORDER BY id`, []string{"id", "name", "ip", "port", "status", "version", "protocol", "comment", "last_test_at", "last_test_message", "meta", "created_at", "updated_at"})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": items, "items": items, "target": "proxy"})
}

func (s *Service) setAgentConfig(w http.ResponseWriter, r *http.Request, params map[string]string) {
	target := strings.ToLower(firstNonEmpty(params["target"], params["node_type"], "proxy"))
	op := strings.ToLower(firstNonEmpty(params["op"], params["action"], "add"))
	if isAgentConnectionTest(params) {
		result := s.testAgentConnection(r.Context(), params)
		_ = s.updateNodeStatus(r.Context(), target, params, asString(result["status"]), asString(result["message"]))
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": result})
		return
	}
	if target == "device" || target == "collector" {
		s.setDeviceConfig(w, r, params, op)
		return
	}
	s.setProxyConfig(w, r, params, op)
}

func isAgentConnectionTest(params map[string]string) bool {
	op := strings.ToLower(firstNonEmpty(params["op"], params["action"]))
	return op == "test" || op == "test_connection"
}

func (s *Service) setProxyConfig(w http.ResponseWriter, r *http.Request, params map[string]string, op string) {
	id := firstNonEmpty(params["id"], params["agent_id"])
	endpoint := parseNodeEndpoint(params)
	ip := endpoint.host
	if op == "del" || op == "delete" || op == "remove" {
		if id != "" {
			_, _ = s.db.ExecContext(r.Context(), `DELETE FROM t_agent WHERE id=?`, id)
		} else if ip != "" {
			_, _ = s.db.ExecContext(r.Context(), `DELETE FROM t_agent WHERE ip=?`, ip)
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "deleted": firstNonEmpty(id, ip)})
		return
	}
	name := firstNonEmpty(params["name"], params["desc"], params["description"], "分析融合节点")
	port := endpoint.port
	version := firstNonEmpty(params["version"], "ta_node")
	status := firstNonEmpty(params["status"], "unknown")
	meta := nodeMeta(params)
	var outID int64
	var err error
	if id != "" {
		_, err = s.db.ExecContext(r.Context(), `
UPDATE t_agent SET name=?, ip=?, port=?, status=?, version=?, meta=?, updated_at=NOW(6)
WHERE id=?`, name, ip, port, status, version, meta, id)
		if err == nil {
			err = s.db.QueryRowContext(r.Context(), `SELECT id FROM t_agent WHERE id=?`, id).Scan(&outID)
		}
	} else {
		// t_agent(ip) 唯一：同 IP 重复保存按 upsert 刷新既有记录（对齐
		// t_device 的 devid 语义），LAST_INSERT_ID(id) 让更新路径也返回原 id。
		var res sql.Result
		res, err = s.db.ExecContext(r.Context(), `
INSERT INTO t_agent (name, ip, port, status, version, meta, updated_at)
VALUES (?,?,?,?,?,?,NOW(6))
ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id), name=VALUES(name), port=VALUES(port),
status=VALUES(status), version=VALUES(version), meta=VALUES(meta), updated_at=NOW(6)`,
			name, ip, port, status, version, meta)
		if err == nil {
			outID, _ = res.LastInsertId()
		}
	}
	if err != nil {
		if isDuplicateKeyErr(err) {
			writeError(w, http.StatusBadRequest, "IP 已被其他节点占用")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{"id": outID, "name": name, "ip": ip, "port": port, "node_type": "proxy"}})
}

func (s *Service) setDeviceConfig(w http.ResponseWriter, r *http.Request, params map[string]string, op string) {
	id := firstNonEmpty(params["id"], params["device_id"])
	devid := firstNonEmpty(params["devid"], params["device_code"], id, fmt.Sprintf("device-%d", time.Now().UnixNano()))
	endpoint := parseNodeEndpoint(params)
	ip := endpoint.host
	if op == "del" || op == "delete" || op == "remove" {
		if id != "" {
			_, _ = s.db.ExecContext(r.Context(), `DELETE FROM t_device WHERE id=?`, id)
		} else {
			_, _ = s.db.ExecContext(r.Context(), `DELETE FROM t_device WHERE devid=?`, devid)
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "deleted": firstNonEmpty(id, devid)})
		return
	}
	name := firstNonEmpty(params["name"], params["desc"], params["description"], "采集节点")
	status := firstNonEmpty(params["status"], "unknown")
	meta := nodeMeta(params)
	var outID int64
	var err error
	if id != "" {
		_, err = s.db.ExecContext(r.Context(), `
UPDATE t_device SET name=?, devid=?, ip=?, status=?, meta=?, updated_at=NOW(6)
WHERE id=?`, name, devid, ip, status, meta, id)
		if err == nil {
			err = s.db.QueryRowContext(r.Context(), `SELECT id FROM t_device WHERE id=?`, id).Scan(&outID)
		}
	} else {
		var res sql.Result
		res, err = s.db.ExecContext(r.Context(), `
INSERT INTO t_device (name, devid, ip, status, meta, updated_at)
VALUES (?,?,?,?,?,NOW(6))
ON DUPLICATE KEY UPDATE
  id=LAST_INSERT_ID(id),
  name=VALUES(name),
  ip=VALUES(ip),
  status=VALUES(status),
  meta=VALUES(meta),
  updated_at=NOW(6)`, name, devid, ip, status, meta)
		if err == nil {
			outID, _ = res.LastInsertId()
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": "ok", "data": map[string]any{"id": outID, "name": name, "devid": devid, "ip": ip, "node_type": "device"}})
}

func (s *Service) testAgentConnection(ctx context.Context, params map[string]string) map[string]any {
	endpoint := parseNodeEndpoint(params)
	ip := endpoint.host
	port := endpoint.port
	protocol := endpoint.protocol
	token := firstNonEmpty(params["token"], params["auth_token"])
	start := time.Now()

	if protocol == "http" || protocol == "https" {
		baseURL := fmt.Sprintf("%s://%s:%d", protocol, ip, port)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/health", nil)
		if err == nil {
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return map[string]any{"status": "online", "reachable": true, "protocol": protocol, "latency_ms": time.Since(start).Milliseconds(), "message": fmt.Sprintf("HTTP %d", resp.StatusCode), "tested_at": time.Now().Format(time.RFC3339Nano)}
				}
				return map[string]any{"status": "warning", "reachable": true, "protocol": protocol, "latency_ms": time.Since(start).Milliseconds(), "message": fmt.Sprintf("HTTP %d", resp.StatusCode), "tested_at": time.Now().Format(time.RFC3339Nano)}
			}
		}
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return map[string]any{"status": "offline", "reachable": false, "protocol": "tcp", "latency_ms": time.Since(start).Milliseconds(), "message": err.Error(), "tested_at": time.Now().Format(time.RFC3339Nano)}
	}
	_ = conn.Close()
	return map[string]any{"status": "online", "reachable": true, "protocol": "tcp", "latency_ms": time.Since(start).Milliseconds(), "message": "TCP connected", "tested_at": time.Now().Format(time.RFC3339Nano)}
}

type nodeEndpoint struct {
	host     string
	port     int
	protocol string
}

func parseNodeEndpoint(params map[string]string) nodeEndpoint {
	protocol := strings.ToLower(firstNonEmpty(params["protocol"], "http"))
	rawHost := firstNonEmpty(params["ip"], params["host"], params["address"], "127.0.0.1")
	portText := firstNonEmpty(params["port"])
	if strings.Contains(rawHost, "://") {
		if req, err := http.NewRequest(http.MethodGet, rawHost, nil); err == nil && req.URL != nil {
			if req.URL.Scheme != "" {
				protocol = strings.ToLower(req.URL.Scheme)
			}
			if req.URL.Hostname() != "" {
				rawHost = req.URL.Hostname()
			}
			if req.URL.Port() != "" && portText == "" {
				portText = req.URL.Port()
			}
		}
	} else if host, port, err := net.SplitHostPort(rawHost); err == nil {
		rawHost = strings.Trim(host, "[]")
		if portText == "" {
			portText = port
		}
	}
	fallbackPort := 19090
	if protocol == "https" {
		fallbackPort = 443
	}
	return nodeEndpoint{
		host:     strings.Trim(rawHost, "[]"),
		port:     parseLimit(firstNonEmpty(portText, strconv.Itoa(fallbackPort)), fallbackPort),
		protocol: protocol,
	}
}

func (s *Service) updateNodeStatus(ctx context.Context, target string, params map[string]string, status string, message string) error {
	meta := nodeMeta(params)
	var m map[string]any
	_ = json.Unmarshal([]byte(meta), &m)
	m["last_test_at"] = time.Now().Format(time.RFC3339Nano)
	m["last_test_message"] = message
	nextMeta, _ := json.Marshal(m)
	id := firstNonEmpty(params["id"], params["device_id"])
	ip := parseNodeEndpoint(params).host
	if target == "device" || target == "collector" {
		if id != "" {
			_, err := s.db.ExecContext(ctx, `UPDATE t_device SET status=?, meta=JSON_MERGE_PATCH(meta, CAST(? AS JSON)), updated_at=NOW(6) WHERE id=?`, status, string(nextMeta), id)
			return err
		}
		_, err := s.db.ExecContext(ctx, `UPDATE t_device SET status=?, meta=JSON_MERGE_PATCH(meta, CAST(? AS JSON)), updated_at=NOW(6) WHERE ip=?`, status, string(nextMeta), ip)
		return err
	}
	id = firstNonEmpty(params["id"], params["agent_id"])
	if id != "" {
		_, err := s.db.ExecContext(ctx, `UPDATE t_agent SET status=?, meta=JSON_MERGE_PATCH(meta, CAST(? AS JSON)), updated_at=NOW(6) WHERE id=?`, status, string(nextMeta), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE t_agent SET status=?, meta=JSON_MERGE_PATCH(meta, CAST(? AS JSON)), updated_at=NOW(6) WHERE ip=?`, status, string(nextMeta), ip)
	return err
}

func nodeMeta(params map[string]string) string {
	meta := map[string]string{}
	for _, key := range []string{"protocol", "port", "comment", "description", "token", "agentid", "flowtype", "interface", "serial"} {
		if v := strings.TrimSpace(params[key]); v != "" {
			meta[key] = v
		}
	}
	if _, ok := meta["protocol"]; !ok {
		meta["protocol"] = "http"
	}
	b, _ := json.Marshal(meta)
	return string(b)
}

func (s *Service) requireDB(w http.ResponseWriter) bool {
	if s == nil || s.db == nil {
		writeCompatUnavailable(w, "ly_server MySQL compatibility database is not configured")
		return false
	}
	if err := s.db.Ping(); err != nil {
		writeCompatUnavailable(w, err.Error())
		return false
	}
	return true
}

func (s *Service) listBW(ctx context.Context, table string) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`SELECT id, value, value_type, description, enabled, created_at, updated_at FROM %s ORDER BY id`, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var value, valueType, desc string
		var enabled bool
		var created, updated time.Time
		if err := rows.Scan(&id, &value, &valueType, &desc, &enabled, &created, &updated); err == nil {
			items = append(items, map[string]any{"id": id, "value": value, "value_type": valueType, "description": desc, "enabled": enabled, "created_at": created, "updated_at": updated})
		}
	}
	return items, nil
}

func (s *Service) queryRows(ctx context.Context, query string, names []string, args ...any) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(names))
		ptrs := make([]any, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		m := map[string]any{}
		for i, name := range names {
			m[name] = normalizeDBValue(vals[i])
		}
		items = append(items, m)
	}
	return items, nil
}

func readParams(r *http.Request) map[string]string {
	params := map[string]string{}
	for k, vals := range r.URL.Query() {
		if len(vals) > 0 {
			params[k] = vals[0]
		}
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			for k, v := range body {
				params[k] = fmt.Sprint(v)
			}
		}
		return params
	}
	_ = r.ParseForm()
	for k, vals := range r.PostForm {
		if len(vals) > 0 {
			params[k] = vals[0]
		}
	}
	return params
}

func normalizeListType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "white", "whitelist", "allow", "allowlist":
		return "white"
	case "black", "blacklist", "deny", "denylist", "block":
		return "black"
	default:
		return ""
	}
}

func jsonValue(b []byte) any {
	if len(b) == 0 {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return string(b)
	}
	return out
}

func normalizeDBValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	case time.Time:
		return x.Format(time.RFC3339Nano)
	case int64, int, int32, bool, string, nil:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"status": "error", "result": "error", "message": message, "code": strconv.Itoa(status)})
}

func writeCompatUnavailable(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"result":  "ok",
		"message": message,
		"data":    []map[string]any{},
		"items":   []map[string]any{},
		"events":  []map[string]any{},
		"total":   0,
		"compat":  "ly_server_unavailable",
	})
}
