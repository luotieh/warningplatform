package boot

import (
	"code.yt-security.com/public/core/v2/web"
)

func LoadWeb(config *Config) *web.Web {
	return web.NewWeb(config.Web)
}
