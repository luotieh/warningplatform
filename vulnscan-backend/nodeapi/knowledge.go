package nodeapi

import (
	"net/http"
	"strconv"
	"time"

	fedSync "vulnscan-backend/federation/sync"
	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
)

func (a *NodeAPI) knowledgeVersionManager() *fedSync.VersionManager {
	a.knowledgeMu.Lock()
	defer a.knowledgeMu.Unlock()
	if a.knowledgeVM == nil {
		a.knowledgeVM = fedSync.NewVersionManager(a.gdb())
	}
	return a.knowledgeVM
}

// KnowledgeManifest returns current PoC / fingerprint / scan-rule sync cursors for scan agents
// (same semantics as federation manifest; uses node X-Agent-Token auth).
func (a *NodeAPI) KnowledgeManifest(c *gin.Context) {
	vm := a.knowledgeVersionManager()
	c.JSON(http.StatusOK, fedSync.ManifestResponse{
		Versions:   vm.AllVersionsFromDB(),
		ServerTime: time.Now(),
	})
}

// KnowledgeSyncPoc incremental PoC templates (since_version cursor).
func (a *NodeAPI) KnowledgeSyncPoc(c *gin.Context) {
	a.knowledgeSync(c, model.SyncDataTypePoc)
}

// KnowledgeSyncFingerprint incremental service fingerprints.
func (a *NodeAPI) KnowledgeSyncFingerprint(c *gin.Context) {
	a.knowledgeSync(c, model.SyncDataTypeFingerprint)
}

// KnowledgeSyncRule incremental generic scan rules (model.ScanRule).
func (a *NodeAPI) KnowledgeSyncRule(c *gin.Context) {
	a.knowledgeSync(c, model.SyncDataTypeRule)
}

func (a *NodeAPI) knowledgeSync(c *gin.Context, dataType string) {
	sinceVersion, _ := strconv.ParseInt(c.Query("since_version"), 10, 64)
	limit, _ := strconv.Atoi(c.Query("limit"))
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	vm := a.knowledgeVersionManager()
	var resp *fedSync.SyncResponse
	var err error
	switch dataType {
	case model.SyncDataTypePoc:
		resp, err = vm.GetPocDelta(sinceVersion, limit)
	case model.SyncDataTypeFingerprint:
		resp, err = vm.GetFingerprintDelta(sinceVersion, limit)
	case model.SyncDataTypeRule:
		resp, err = vm.GetRuleDelta(sinceVersion, limit)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown data type"})
		return
	}
	if err != nil {
		web.Fail(c).Msg("sync failed").Err(err).Send()
		return
	}
	c.JSON(http.StatusOK, resp)
}
