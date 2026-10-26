package core

import (
	"bytes"
	"strings"
	"sync"

	"vault443/internal/journal"
)

// outputWriter is drained by os/exec's copying goroutine. It never waits for
// journal disk I/O and discards oversized lines until the next delimiter so a
// malicious/unusually verbose core cannot exhaust memory or block its pipe.
type outputWriter struct {
	mu       sync.Mutex
	session  *journal.Session
	partial  []byte
	skipping bool
}

func newOutputWriter(s *journal.Session) *outputWriter { return &outputWriter{session: s} }
func (w *outputWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(p) > 0 {
		end := bytes.IndexByte(p, '\n')
		chunk := p
		if end >= 0 {
			chunk = p[:end]
		}
		if !w.skipping {
			if len(w.partial)+len(chunk) > journal.MaxMessageBytes*4 {
				w.partial = nil
				w.skipping = true
			} else {
				w.partial = append(w.partial, chunk...)
			}
		}
		if end < 0 {
			break
		}
		w.emit()
		p = p[end+1:]
	}
	return n, nil
}
func (w *outputWriter) Flush() { w.mu.Lock(); defer w.mu.Unlock(); w.emit() }
func (w *outputWriter) emit() {
	if w.skipping {
		w.session.Log("warning", "Xray: overlong output line omitted")
	} else if len(w.partial) > 0 {
		line := strings.TrimSpace(string(w.partial))
		level := "info"
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "[debug]"):
			level = "debug"
		case strings.Contains(lower, "[warning]"), strings.Contains(lower, "[warn]"):
			level = "warning"
		case strings.Contains(lower, "[error]"), strings.Contains(lower, "[fatal]"):
			level = "error"
		}
		w.session.Log(level, "Xray: "+line)
	}
	w.partial = w.partial[:0]
	w.skipping = false
}
