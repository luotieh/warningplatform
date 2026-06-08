package scanrunner

import (
	"log/slog"

	"gorm.io/gorm"

	"code.yt-security.com/public/scanengine/dict"
	"code.yt-security.com/public/scanengine/rulestore"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/payload"
)

func logKnowledgeBootstrap(db *gorm.DB, ds *dict.Store, rs *rulestore.Store, pl *payload.Loader) {
	if db == nil {
		slog.Warn("[Knowledge] 未连接数据库，扫描将使用内嵌字典/规则与空 payload 兜底")
		return
	}

	for _, cat := range payload.VulnPayloadCategories {
		if len(pl.GetPayloads(cat)) == 0 {
			slog.Warn("[Knowledge] 数据文库无 payload，漏洞模块将使用代码内嵌兜底",
				"category", cat, "hint", "知识库 → 数据文库，类型 payload")
		}
	}

	dictTypes := []struct {
		typ  string
		name string
	}{
		{model.DictTypeSubdomain, "子域名"},
		{model.DictTypeDirpath, "目录"},
		{model.DictTypeUsername, "用户名"},
		{model.DictTypePassword, "密码"},
	}
	for _, d := range dictTypes {
		if !ds.HasDBEntries(d.typ) {
			slog.Info("[Knowledge] 字典使用内嵌默认", "type", d.typ, "label", d.name,
				"hint", "可在知识库 → 数据文库维护对应类型字典")
		}
	}

	for _, rt := range []string{model.RuleTypeWAFDetect, model.RuleTypeTechDetect, model.RuleTypeJSAnalyze} {
		n := len(rs.Get(rt))
		slog.Info("[Knowledge] 规则已加载", "type", rt, "count", n)
	}
}
