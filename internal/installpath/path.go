// Package installpath validates the narrowly supported Windows installation
// locations before a privileged installer or service uses their contents.
package installpath

import (
	"errors"
	"strings"
	"unicode/utf16"
)

// Canonical deliberately accepts only ordinary drive-letter paths. Device
// namespaces, ADS, drive-relative paths, dot aliases and Win32's trailing-space
// normalization must never select a different object than the checked one.
func Canonical(path string) (string, error) {
	path = strings.ReplaceAll(path, "/", `\`)
	if len(path) < 4 || ((path[0] < 'A' || path[0] > 'Z') && (path[0] < 'a' || path[0] > 'z')) || path[1:3] != `:\` {
		return "", errors.New("select an absolute local drive path below its root")
	}
	path = strings.TrimSuffix(path, `\`)
	if len(utf16.Encode([]rune(path))) > 240 {
		return "", errors.New("installation path exceeds 240 UTF-16 characters")
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", errors.New("installation path contains an ambiguous component")
		}
		for _, c := range part {
			if c < 32 || strings.ContainsRune(`<>:"|?*`, c) {
				return "", errors.New("installation path contains an invalid character")
			}
		}
		name := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "CONIN$" || name == "CONOUT$" ||
			((strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) && len([]rune(name)) == 4 && strings.ContainsRune("123456789¹²³", []rune(name)[3])) {
			return "", errors.New("installation path contains a reserved device name")
		}
	}
	return strings.ToUpper(path[:1]) + path[1:], nil
}
