package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CredentialsFile matches JSON from POST /cluster/scan-nodes/enroll (node-agent.credentials.json).
type CredentialsFile struct {
	Version   int    `json:"version"`
	MasterURL string `json:"master_url"`
	NodeUUID  string `json:"node_uuid"`
	Secret    string `json:"secret"`
	IssuedAt  string `json:"issued_at"`
	Label     string `json:"label,omitempty"`
	Topology  string `json:"topology,omitempty"`
}

// LoadCredentialsFile reads a credentials JSON file issued by the master.
func LoadCredentialsFile(path string) (*CredentialsFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// 去掉 UTF-8 BOM（部分编辑器保存 JSON 时会带上）
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	var f CredentialsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	applyCredentialsAliases(b, &f)
	f.MasterURL = strings.TrimSpace(f.MasterURL)
	f.NodeUUID = strings.TrimSpace(f.NodeUUID)
	f.Secret = strings.TrimSpace(f.Secret)
	if f.NodeUUID == "" || f.Secret == "" {
		return nil, fmt.Errorf("credentials file missing node_uuid or secret")
	}
	return &f, nil
}

func applyCredentialsAliases(raw []byte, f *CredentialsFile) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				var s string
				if err := json.Unmarshal(v, &s); err == nil {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}
	if f.NodeUUID == "" {
		f.NodeUUID = pick("node_uuid", "nodeUuid", "uuid", "token")
	}
	if f.Secret == "" {
		f.Secret = pick("secret", "agent_secret", "node_secret")
	}
	if f.MasterURL == "" {
		f.MasterURL = pick("master_url", "masterUrl", "masterURL")
	}
	if f.Topology == "" {
		f.Topology = pick("topology")
	}
}
