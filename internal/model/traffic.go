package model

import "time"

// TUNCounters is an internal observation of one owned kernel interface. Epoch
// changes before each core launch; IfIndex distinguishes recreated interfaces.
// SampledAt retains Go's monotonic clock for rate calculations.
type TUNCounters struct {
	Epoch     uint64
	IfIndex   uint64
	RXBytes   uint64
	TXBytes   uint64
	SampledAt time.Time
	Valid     bool
}

// Traffic is session accounting, not the lifetime counters of a kernel device.
// Timestamps are Unix milliseconds, matching the operation API. Data is kept in
// memory only and is returned exclusively to the session's owner.
type Traffic struct {
	SessionID              string  `json:"sessionId"`
	StartedAt              int64   `json:"startedAt"`
	DurationSeconds        int64   `json:"durationSeconds"`
	DownloadBytes          uint64  `json:"downloadBytes"`
	UploadBytes            uint64  `json:"uploadBytes"`
	DownloadBytesPerSecond float64 `json:"downloadBytesPerSecond"`
	UploadBytesPerSecond   float64 `json:"uploadBytesPerSecond"`
	MeasuredAt             int64   `json:"measuredAt"`
	Valid                  bool    `json:"valid"`
}
