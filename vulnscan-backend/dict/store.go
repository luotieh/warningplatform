package dict

import (
	"bufio"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// Store 统一字典管理
type Store struct {
	mu       sync.RWMutex
	builtins map[string][]string // type → entries
	db       *gorm.DB
}

func NewStore(db *gorm.DB) *Store {
	s := &Store{
		builtins: make(map[string][]string),
		db:       db,
	}
	s.loadBuiltins()
	return s
}

// Get 获取字典内容 — 优先级: 自定义字典名 > DB > 内嵌
func (s *Store) Get(dictType string, name string) []string {
	if name != "" && s.db != nil {
		entries := s.loadFromDB(name)
		if len(entries) > 0 {
			return entries
		}
	}

	if s.db != nil {
		entries := s.loadByType(dictType)
		if len(entries) > 0 {
			return entries
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.builtins[dictType]
}

// GetSubdomains 获取子域名字典
func (s *Store) GetSubdomains() []string {
	return s.Get(model.DictTypeSubdomain, "")
}

// GetDirpaths 获取目录路径字典
func (s *Store) GetDirpaths() []string {
	return s.Get(model.DictTypeDirpath, "")
}

// GetUsernames 获取用户名字典
func (s *Store) GetUsernames() []string {
	return s.Get(model.DictTypeUsername, "")
}

// GetPasswords 获取密码字典
func (s *Store) GetPasswords() []string {
	return s.Get(model.DictTypePassword, "")
}

// LoadFromFile 从文件加载字典
func (s *Store) LoadFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	return entries, scanner.Err()
}

// Merge 合并多个字典（去重）
func (s *Store) Merge(sources ...[]string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, src := range sources {
		for _, entry := range src {
			if _, ok := seen[entry]; !ok {
				seen[entry] = struct{}{}
				result = append(result, entry)
			}
		}
	}
	return result
}

func (s *Store) loadFromDB(name string) []string {
	var lib model.DataLibrary
	if err := s.db.Where("name = ? AND status = ?", name, model.DataLibStatusActive).First(&lib).Error; err != nil {
		return nil
	}

	var entries []model.DataLibraryEntry
	if err := s.db.Where("library_id = ? AND enabled = ?", lib.ID, true).Order("priority DESC").Find(&entries).Error; err != nil {
		return nil
	}

	result := make([]string, 0, len(entries))
	for _, e := range entries {
		result = append(result, e.Value)
	}
	return result
}

func (s *Store) loadByType(dictType string) []string {
	var libs []model.DataLibrary
	if err := s.db.Where("type = ? AND status = ?", dictType, model.DataLibStatusActive).Find(&libs).Error; err != nil || len(libs) == 0 {
		return nil
	}

	var ids []string
	for _, d := range libs {
		ids = append(ids, d.ID)
	}

	var entries []model.DataLibraryEntry
	if err := s.db.Where("library_id IN ? AND enabled = ?", ids, true).Order("priority DESC").Find(&entries).Error; err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var result []string
	for _, e := range entries {
		if _, ok := seen[e.Value]; !ok {
			seen[e.Value] = struct{}{}
			result = append(result, e.Value)
		}
	}
	return result
}

func (s *Store) loadBuiltins() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.builtins[model.DictTypeSubdomain] = builtinSubdomains()
	s.builtins[model.DictTypeDirpath] = builtinDirpaths()
	s.builtins[model.DictTypeUsername] = builtinUsernames()
	s.builtins[model.DictTypePassword] = builtinPasswords()

	for t, entries := range s.builtins {
		slog.Debug("[*] 内嵌字典已加载", "type", t, "count", len(entries))
	}
}
