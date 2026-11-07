//go:build windows

package service

import stdlog "log"

// Raw native errors belong only in the daemon's protected service.log. Profile
// journals and IPC keep their existing generic/sanitized cleanup messages.
func privateWorkCleanupError(profileID, stage string, err error) {
	if err != nil {
		stdlog.Printf("Windows work cleanup profile=%q stage=%s: %v", profileID, stage, err)
	}
}
