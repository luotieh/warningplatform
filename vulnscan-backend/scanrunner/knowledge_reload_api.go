package scanrunner

import (
	"code.yt-security.com/public/core/web"
	"github.com/gin-gonic/gin"
)

func (a *API) ReloadKnowledge(c *gin.Context) {
	reg := DefaultKnowledgeRegistry()
	if reg == nil {
		web.Fail(c).Msg("扫描知识库未初始化").Send()
		return
	}
	if err := reg.ReloadAll(); err != nil {
		web.Fail(c).Err(err).Send()
		return
	}
	web.Succeed(c).Msg("扫描知识库已重载（payload、规则、PoC 缓存）").Send()
}
