package asset

import (
	"context"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/scanengine/core"
	"code.yt-security.com/public/scanengine/module/screenshot"
	"vulnscan-backend/boot"
	"vulnscan-backend/model"

	iamsdk "code.yt-security.com/public/access"
	"code.yt-security.com/public/access/storage"
	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type ScreenshotService struct {
	db             *db.DB
	iam            *iamsdk.Client
	mod            *screenshot.ScreenshotModule
	storageBaseURL string
}

func NewScreenshotService(database *db.DB, iam *iamsdk.Client, cfg *boot.Config) *ScreenshotService {
	storageBase := strings.TrimRight(cfg.IAM.BaseURL, "/") + cfg.IAM.PathPrefix + "/storage/file"
	return &ScreenshotService{
		db:             database,
		iam:            iam,
		mod:            screenshot.New(),
		storageBaseURL: storageBase,
	}
}

func (s *ScreenshotService) FileDownloadURL(fileID string) string {
	if fileID == "" || s.storageBaseURL == "" {
		return ""
	}
	return s.storageBaseURL + "/" + fileID + "/content"
}

func (s *ScreenshotService) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *ScreenshotService) uploadToStorage(ctx context.Context, assetID string, jpegData []byte, userID ...string) (string, error) {
	if s.iam == nil {
		return "", nil
	}

	req := storage.FileUploadRequest{
		PolicyCode:  "default",
		FileName:    "screenshot-" + assetID + ".jpg",
		ContentType: "image/jpeg",
		Data:        jpegData,
		BizType:     "asset_screenshot",
		BizID:       assetID,
		App:         "vulnscan",
	}
	if len(userID) > 0 && userID[0] != "" {
		req.UserID = userID[0]
	}
	file, err := s.iam.Storage.UploadSimpleAsService(ctx, req)
	if err != nil {
		return "", err
	}
	return file.ID, nil
}

// CaptureAndSave captures a screenshot of the asset's address and saves it to IAM Storage.
// Designed to be called asynchronously via goroutine.
func (s *ScreenshotService) CaptureAndSave(assetID, address string) {
	if address == "" || assetID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	target := &core.Target{URL: normalizeScreenshotURL(address)}
	result, err := s.mod.Run(ctx, []*core.Target{target}, nil)
	if err != nil || result == nil || len(result.Findings) == 0 {
		slog.Debug("asset screenshot capture: no result", "asset_id", assetID, "address", address)
		return
	}

	for _, f := range result.Findings {
		b64, ok := f.Data["screenshot"]
		if !ok || b64 == "" {
			continue
		}

		jpegData, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			slog.Warn("screenshot base64 decode failed", "asset_id", assetID, "error", err)
			s.fallbackSaveBase64(assetID, b64)
			return
		}

		fileID, err := s.uploadToStorage(ctx, assetID, jpegData)
		if err != nil || fileID == "" {
			slog.Warn("screenshot upload to storage failed, fallback to db", "asset_id", assetID, "error", err)
			s.fallbackSaveBase64(assetID, b64)
			return
		}

		if err := s.session().Model(&model.Asset{}).Where("id = ?", assetID).
			Update("screenshot", fileID).Error; err != nil {
			slog.Warn("asset screenshot id save failed", "asset_id", assetID, "error", err)
		} else {
			slog.Info("asset screenshot saved to storage", "asset_id", assetID, "file_id", fileID)
		}
		return
	}
}

func (s *ScreenshotService) fallbackSaveBase64(assetID, b64 string) {
	if err := s.session().Model(&model.Asset{}).Where("id = ?", assetID).
		Update("screenshot", b64).Error; err != nil {
		slog.Warn("asset screenshot fallback save failed", "asset_id", assetID, "error", err)
	}
}

// RefreshScreenshot re-captures a screenshot for the given asset.
// userID 可选，传入操作者 ID 以记录上传人。
func (s *ScreenshotService) RefreshScreenshot(ctx context.Context, assetID string, userID ...string) (string, error) {
	var asset model.Asset
	if err := s.session().Select("id, address, screenshot").First(&asset, "id = ?", assetID).Error; err != nil {
		return "", err
	}
	if asset.Address == "" {
		return "", nil
	}

	captureCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	target := &core.Target{URL: normalizeScreenshotURL(asset.Address)}
	result, err := s.mod.Run(captureCtx, []*core.Target{target}, nil)
	if err != nil || result == nil || len(result.Findings) == 0 {
		return "", nil
	}

	for _, f := range result.Findings {
		b64, ok := f.Data["screenshot"]
		if !ok || b64 == "" {
			continue
		}

		jpegData, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			_ = s.session().Model(&model.Asset{}).Where("id = ?", assetID).
				Update("screenshot", b64).Error
			return b64, nil
		}

		uploadReq := storage.FileUploadRequest{
			PolicyCode:  "default",
			FileName:    "screenshot-" + assetID + ".jpg",
			ContentType: "image/jpeg",
			Data:        jpegData,
			BizType:     "asset_screenshot",
			BizID:       assetID,
			App:         "vulnscan",
		}
		if len(userID) > 0 && userID[0] != "" {
			uploadReq.UserID = userID[0]
		}
		file, uploadErr := s.iam.Storage.UploadSimpleAsService(captureCtx, uploadReq)
		if uploadErr != nil || file == nil {
			_ = s.session().Model(&model.Asset{}).Where("id = ?", assetID).
				Update("screenshot", b64).Error
			return b64, nil
		}

		_ = s.session().Model(&model.Asset{}).Where("id = ?", assetID).
			Update("screenshot", file.ID).Error
		return file.ID, nil
	}
	return "", nil
}

func isBase64Screenshot(val string) bool {
	return len(val) > 100
}

func normalizeScreenshotURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, "://") {
		return "http://" + addr
	}
	return addr
}
