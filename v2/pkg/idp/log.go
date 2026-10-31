package idp

import (
	"context"
	"log/slog"

	"github.com/rs/zerolog"
)

// zerologHandler passes the OIDC library's slog records to glauth's logger. The
// library logs routine client errors at info and above, so it is shifted down a
// level to keep glauth's own sign-in messages prominent.
type zerologHandler struct {
	log zerolog.Logger
}

func (h zerologHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.log.GetLevel() <= zerologLevel(level)
}

func (h zerologHandler) Handle(_ context.Context, r slog.Record) error {
	e := h.log.WithLevel(zerologLevel(r.Level))
	r.Attrs(func(a slog.Attr) bool {
		e = e.Interface(a.Key, a.Value.Any())
		return true
	})
	e.Str("component", "oidc").Msg(r.Message)
	return nil
}

func (h zerologHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	ctx := h.log.With()
	for _, a := range attrs {
		ctx = ctx.Interface(a.Key, a.Value.Any())
	}
	return zerologHandler{ctx.Logger()}
}

func (h zerologHandler) WithGroup(string) slog.Handler { return h }

func zerologLevel(level slog.Level) zerolog.Level {
	switch {
	case level >= slog.LevelError:
		return zerolog.WarnLevel
	case level >= slog.LevelWarn:
		return zerolog.InfoLevel
	default:
		return zerolog.DebugLevel
	}
}

// SlogHandler returns an slog.Handler that writes to log.
func SlogHandler(log zerolog.Logger) slog.Handler {
	return zerologHandler{log}
}
