package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// SetupCLILogger 配置面向终端的可读文本日志（非 JSON）。
func SetupCLILogger(level slog.Level, w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	slog.SetDefault(slog.New(NewCLIHandler(w, &slog.HandlerOptions{Level: level})))
}

// CLIHandler 将日志格式化为：时间 [级别] 消息 key=value …
type CLIHandler struct {
	leveler slog.Leveler
	w       io.Writer
	mu      sync.Mutex
}

func NewCLIHandler(w io.Writer, opts *slog.HandlerOptions) *CLIHandler {
	var leveler slog.Leveler = slog.LevelInfo
	if opts != nil && opts.Level != nil {
		leveler = opts.Level
	}
	return &CLIHandler{leveler: leveler, w: w}
}

func (h *CLIHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.leveler.Level()
}

func (h *CLIHandler) Handle(_ context.Context, r slog.Record) error {
	if !h.Enabled(context.Background(), r.Level) {
		return nil
	}
	parts := make([]string, 0, 4)
	r.Attrs(func(a slog.Attr) bool {
		k, v := formatCLIAttr(a)
		if k != "" && v != "" {
			parts = append(parts, k+"="+v)
		}
		return true
	})
	line := fmt.Sprintf("%s [%s] %s",
		r.Time.Local().Format("2006-01-02 15:04:05"),
		levelLabelCN(r.Level),
		r.Message,
	)
	if len(parts) > 0 {
		line += " " + strings.Join(parts, " ")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprintln(h.w, line)
	return err
}

func (h *CLIHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *CLIHandler) WithGroup(string) slog.Handler            { return h }

func levelLabelCN(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "错误"
	case level >= slog.LevelWarn:
		return "警告"
	case level >= slog.LevelInfo:
		return "信息"
	default:
		return "调试"
	}
}

func formatCLIAttr(a slog.Attr) (string, string) {
	switch a.Value.Kind() {
	case slog.KindString:
		return a.Key, a.Value.String()
	case slog.KindInt64:
		return a.Key, fmt.Sprintf("%d", a.Value.Int64())
	case slog.KindUint64:
		return a.Key, fmt.Sprintf("%d", a.Value.Uint64())
	case slog.KindFloat64:
		return a.Key, fmt.Sprintf("%g", a.Value.Float64())
	case slog.KindBool:
		return a.Key, fmt.Sprintf("%t", a.Value.Bool())
	case slog.KindDuration:
		return a.Key, a.Value.Duration().String()
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok {
			return a.Key, FormatErrorDetail(err)
		}
		return a.Key, fmt.Sprint(a.Value.Any())
	default:
		return a.Key, a.Value.String()
	}
}
