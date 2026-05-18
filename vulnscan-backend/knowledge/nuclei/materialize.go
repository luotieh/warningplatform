package nuclei

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// pocTemplateCacheBase 返回 PoC 原始 YAML 内容寻址缓存根目录。
// 可通过环境变量 VULNSCAN_NUCLEI_POCS_CACHE_DIR 覆盖（便于测试或指定磁盘）。
func pocTemplateCacheBase() string {
	if d := strings.TrimSpace(os.Getenv("VULNSCAN_NUCLEI_POCS_CACHE_DIR")); d != "" {
		return filepath.Clean(d)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "vulnscan-nuclei-poc")
	}
	return filepath.Join(base, "vulnscan", "nuclei-poc-bytes")
}

// materializePocTemplates 将 PoC 内容稳定落盘（按内容哈希去重），返回供 Nuclei SDK 使用的模板文件路径列表。
// Nuclei 加载器以路径为入口；内容寻址可避免每次任务全量写入临时目录，并天然合并相同 YAML。
func materializePocTemplates(entries []*PocEntry) ([]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	root := pocTemplateCacheBase()
	seen := make(map[string]struct{}, len(entries))
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e == nil || strings.TrimSpace(e.RawContent) == "" {
			continue
		}
		raw := []byte(e.RawContent)
		sum := sha256.Sum256(raw)
		hexFull := hex.EncodeToString(sum[:])
		shard := hexFull[:2]
		dest := filepath.Join(root, shard, hexFull+".yaml")
		if err := writeTemplateIfChanged(dest, raw); err != nil {
			return nil, fmt.Errorf("materialize template %s: %w", e.ID, err)
		}
		if _, ok := seen[dest]; ok {
			continue
		}
		seen[dest] = struct{}{}
		paths = append(paths, dest)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	return paths, nil
}

func writeTemplateIfChanged(dest string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	if existing, err := os.ReadFile(dest); err == nil && bytes.Equal(existing, content) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".nuclei-poc-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	_ = os.Remove(dest)
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
