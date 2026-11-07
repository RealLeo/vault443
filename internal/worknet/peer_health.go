package worknet

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"vault443/internal/workvpn"
)

const wgInitialTimeout = 60 * time.Second
const wgPeerRetry = 30 * time.Second

type wgHealth struct {
	ConfirmedAt time.Time
	NoProbe     bool
	Ready       bool
	Handshake   int64
	CheckingAt  time.Time
	LastProbe   time.Time
	LastResolve time.Time
	Observation wgPeerObservation
}

func workInterface(id string) string {
	h := sha256.Sum256([]byte(id))
	return "v443w" + hex.EncodeToString(h[:4])
}

func wgKeyLifetime(w *workvpn.WireGuardConfig) time.Duration {
	value := w.Parameters["RejectAfterTime"]
	if value != "" {
		parts := strings.Split(value, "-")
		if n, e := strconv.ParseUint(parts[len(parts)-1], 10, 32); e == nil && n > 0 {
			return time.Duration(n)*time.Second + 10*time.Second
		}
	}
	return 190 * time.Second
}

// Readiness is based on successful authentication, not just link UP or an old
// handshake timestamp. An idle peer remains ready during a bounded active check.
func updateWGHealth(h *wgHealth, o wgPeerObservation, now, started time.Time, lifetime time.Duration) {
	if o.Handshake >= started.Unix() && o.Handshake > h.Handshake && o.Handshake <= now.Add(5*time.Second).Unix() {
		h.Handshake = o.Handshake
		h.Ready = true
		h.CheckingAt = time.Time{}
		h.ConfirmedAt = now
	}
	if h.Ready && h.CheckingAt.IsZero() && now.Sub(h.ConfirmedAt) > lifetime {
		h.CheckingAt = now
	}
	if !h.CheckingAt.IsZero() && now.Sub(h.CheckingAt) > wgInitialTimeout {
		h.Ready = false
	}
}

type wgPeerObservation struct {
	Handshake int64
	RX, TX    uint64
	Endpoint  string
}
