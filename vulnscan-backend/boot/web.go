package boot

import (
	"code.yt-security.com/public/core/web"
)

func LoadWeb(config *Config) *web.Engine {
	return web.New(config.Web)
}
