package tests

import (
	"log/slog"

	"github.com/rlebel12/gosesh"
)

func prepareSlogger() (gosesh.NewOpts, *slogWriter) {
	// Returns an option to be passed to gosesh.New and a slogWriter to capture logs
	testSlogger := newSlogWriter()
	return func(g *gosesh.Gosesh) {
		handler := slog.NewTextHandler(testSlogger, nil)
		gosesh.WithLogger(slog.New(handler))(g)
	}, testSlogger
}

func newSlogWriter() *slogWriter {
	return new(slogWriter)
}

type slogWriter struct {
	logs []string
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	w.logs = append(w.logs, string(p))
	return len(p), nil
}
