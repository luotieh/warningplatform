package sync

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"

	"vulnscan-backend/model"
)

// VersionManager manages sync version numbers on the Central Master side.
type VersionManager struct {
	db      *gorm.DB
	mu      sync.Mutex
	current map[string]int64
}

func NewVersionManager(db *gorm.DB) *VersionManager {
	vm := &VersionManager{
		db:      db,
		current: make(map[string]int64),
	}
	vm.loadCurrent()
	return vm
}

func (vm *VersionManager) loadCurrent() {
	var rows []model.SyncVersion
	if err := vm.db.Find(&rows).Error; err != nil {
		slog.Warn("[VersionManager] 加载版本号失败", "error", err)
		return
	}
	for _, r := range rows {
		vm.current[r.DataType] = r.CurrentVersion
	}

	for _, dt := range []string{model.SyncDataTypePoc, model.SyncDataTypeFingerprint, model.SyncDataTypeRule} {
		if _, ok := vm.current[dt]; !ok {
			rec := model.SyncVersion{DataType: dt, CurrentVersion: 0, UpdatedAt: time.Now()}
			vm.db.Create(&rec)
			vm.current[dt] = 0
		}
	}
}

// Bump increments the version for a data type and returns the new version.
func (vm *VersionManager) Bump(dataType string) int64 {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.current[dataType]++
	newVer := vm.current[dataType]

	vm.db.Model(&model.SyncVersion{}).
		Where("data_type = ?", dataType).
		Updates(map[string]interface{}{
			"current_version": newVer,
			"updated_at":      time.Now(),
		})

	return newVer
}

// Current returns the current version for a data type.
func (vm *VersionManager) Current(dataType string) int64 {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return vm.current[dataType]
}

// LatestVersionFromDB reads the aggregate sync cursor for a data type from cm_sync_version
// (authoritative for federation / node knowledge sync responses).
func (vm *VersionManager) LatestVersionFromDB(dataType string) int64 {
	var row model.SyncVersion
	if err := vm.db.Where("data_type = ?", dataType).First(&row).Error; err != nil {
		return 0
	}
	return row.CurrentVersion
}

// AllVersionsFromDB returns sync cursors from cm_sync_version (DB-authoritative).
func (vm *VersionManager) AllVersionsFromDB() map[string]int64 {
	out := make(map[string]int64)
	for _, dt := range []string{model.SyncDataTypePoc, model.SyncDataTypeFingerprint, model.SyncDataTypeRule} {
		out[dt] = vm.LatestVersionFromDB(dt)
	}
	return out
}

// AllVersions returns all current versions.
func (vm *VersionManager) AllVersions() map[string]int64 {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	out := make(map[string]int64, len(vm.current))
	for k, v := range vm.current {
		out[k] = v
	}
	return out
}

// GetPocDelta returns PoC records changed since sinceVersion, up to limit.
func (vm *VersionManager) GetPocDelta(sinceVersion int64, limit int) (*SyncResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	var records []model.PocTemplate
	err := vm.db.Unscoped().
		Where("sync_version > ?", sinceVersion).
		Order("sync_version ASC").
		Limit(limit + 1).
		Find(&records).Error
	if err != nil {
		return nil, err
	}

	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}

	items := make([]SyncItem, 0, len(records))
	for _, r := range records {
		item := SyncItem{
			SyncVersion: r.SyncVersion,
			DataType:    model.SyncDataTypePoc,
			DataID:      r.PocID,
		}

		if r.UpdatedAt.IsZero() && r.CreatedAt.IsZero() {
			item.Action = "delete"
		} else {
			item.Action = "upsert"
			content, _ := json.Marshal(r)
			item.Content = content
		}
		items = append(items, item)
	}

	return &SyncResponse{
		Items:         items,
		LatestVersion: vm.LatestVersionFromDB(model.SyncDataTypePoc),
		HasMore:       hasMore,
		ServerTime:    time.Now(),
	}, nil
}

// GetFingerprintDelta returns fingerprint records changed since sinceVersion.
func (vm *VersionManager) GetFingerprintDelta(sinceVersion int64, limit int) (*SyncResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	var records []model.ServiceFingerprint
	err := vm.db.Unscoped().
		Where("sync_version > ?", sinceVersion).
		Order("sync_version ASC").
		Limit(limit + 1).
		Find(&records).Error
	if err != nil {
		return nil, err
	}

	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}

	items := make([]SyncItem, 0, len(records))
	for _, r := range records {
		item := SyncItem{
			SyncVersion: r.SyncVersion,
			DataType:    model.SyncDataTypeFingerprint,
			DataID:      r.ID,
			Action:      "upsert",
		}
		content, _ := json.Marshal(r)
		item.Content = content
		items = append(items, item)
	}

	return &SyncResponse{
		Items:         items,
		LatestVersion: vm.LatestVersionFromDB(model.SyncDataTypeFingerprint),
		HasMore:       hasMore,
		ServerTime:    time.Now(),
	}, nil
}

// GetRuleDelta returns scan rule records changed since sinceVersion.
func (vm *VersionManager) GetRuleDelta(sinceVersion int64, limit int) (*SyncResponse, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	var records []model.ScanRule
	err := vm.db.Unscoped().
		Where("sync_version > ?", sinceVersion).
		Order("sync_version ASC").
		Limit(limit + 1).
		Find(&records).Error
	if err != nil {
		return nil, err
	}

	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}

	items := make([]SyncItem, 0, len(records))
	for _, r := range records {
		item := SyncItem{
			SyncVersion: r.SyncVersion,
			DataType:    model.SyncDataTypeRule,
			DataID:      r.ID,
			Action:      "upsert",
		}
		content, _ := json.Marshal(r)
		item.Content = content
		items = append(items, item)
	}

	return &SyncResponse{
		Items:         items,
		LatestVersion: vm.LatestVersionFromDB(model.SyncDataTypeRule),
		HasMore:       hasMore,
		ServerTime:    time.Now(),
	}, nil
}

// LogSync records a sync operation for audit trail.
func (vm *VersionManager) LogSync(subMasterID, dataType string, from, to int64, count int, status string, errMsg string, durMs int) {
	log := model.SyncLog{
		ID:           ulid.GenerateID(),
		SubMasterID:  subMasterID,
		DataType:     dataType,
		FromVersion:  from,
		ToVersion:    to,
		RecordCount:  count,
		Status:       status,
		ErrorMessage: errMsg,
		DurationMs:   durMs,
		SyncedAt:     time.Now(),
	}
	if err := vm.db.Create(&log).Error; err != nil {
		slog.Warn("[VersionManager] 记录同步日志失败", "error", err)
	}
}
