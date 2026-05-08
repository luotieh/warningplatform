package frontend

import (
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetupSPA(engine *gin.Engine, notFoundHandler gin.HandlerFunc) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return
	}

	fileServer := http.FileServer(http.FS(sub))
	engine.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		f, openErr := sub.Open(path[1:])
		if openErr == nil {
			f.Close()
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}
		indexFile, indexErr := sub.Open("index.html")
		if indexErr != nil {
			if notFoundHandler != nil {
				notFoundHandler(c)
			}
			return
		}
		indexFile.Close()
		c.Request.URL.Path = "/"
		fileServer.ServeHTTP(c.Writer, c.Request)
	})
}
