package ws

import (
	"log/slog"
	"net/http"

	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WSHandler exposes the WebSocket endpoint for worker connections.
type WSHandler struct {
	hub *Hub
}

func NewWSHandler(hub *Hub) *WSHandler {
	return &WSHandler{hub: hub}
}

// HandleConnect upgrades HTTP to WebSocket and registers the worker connection.
func (h *WSHandler) HandleConnect(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("[WS] WebSocket 升级失败", "error", err)
		return
	}

	h.hub.HandleWorkerConn(conn)
}

// RegisterRoutes adds the WebSocket endpoint to the router.
func (h *WSHandler) RegisterRoutes(router *gin.RouterGroup) {
	router.GET("/ws", h.HandleConnect)
}

// Status returns hub statistics as JSON.
func (h *WSHandler) Status(c *gin.Context) {
	web.OK(c).Data(map[string]interface{}{
		"connected_workers": h.hub.WorkerCount(),
		"worker_ids":        h.hub.OnlineWorkerIDs(),
	}).Send()
}
