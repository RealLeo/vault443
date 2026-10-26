package network

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// OpenVPN UDP sockets are usually unconnected: ss cannot reveal their peer.
// Read only a verified root process's numeric transport directives. Never
// execute directives, follow included files, resolve names, or retain secrets.
func processOpenVPNEndpoints(pid string) []Endpoint {
	b, e := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if e != nil || len(b) > 64<<10 {
		return nil
	}
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	if len(args) < 2 {
		return nil
	}
	return openVPNEndpoints(args[1:], func(path string) ([]byte, error) {
		if !filepath.IsAbs(path) {
			cwd, e := os.Readlink(filepath.Join("/proc", pid, "cwd"))
			if e != nil {
				return nil, e
			}
			path = filepath.Join(cwd, path)
		}
		return readRootConfig(path)
	})
}

func readRootConfig(path string) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "OpenVPN metadata")
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > 1<<20 {
		return nil, os.ErrPermission
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(b) > 1<<20 {
		return nil, os.ErrPermission
	}
	return b, e
}

func openVPNEndpoints(args []string, readConfig func(string) ([]byte, error)) []Endpoint {
	var directives [][]string
	for i := 0; i < len(args); i++ {
		key := strings.TrimPrefix(args[i], "--")
		switch key {
		case "config":
			if i+1 >= len(args) {
				return nil
			}
			i++
			b, e := readConfig(args[i])
			if e != nil {
				return nil
			}
			inline := false
			for _, line := range bytes.Split(b, []byte{'\n'}) {
				s := strings.TrimSpace(string(line))
				if strings.HasPrefix(s, "</") {
					inline = false
					continue
				}
				if strings.HasPrefix(s, "<") {
					// Per-connection options require a richer manager adapter.
					if strings.HasPrefix(s, "<connection>") {
						return nil
					}
					inline = true
					continue
				}
				if inline {
					continue
				}
				fields, ok := metadataFields(s)
				if !ok || len(fields) == 0 {
					continue
				}
				fields[0] = strings.TrimPrefix(fields[0], "--")
				switch fields[0] {
				case "remote", "proto", "port", "rport":
					directives = append(directives, fields)
				case "config":
					return nil // no recursive/indirect config reads
				}
			}
		case "proto", "port", "rport", "remote":
			d := []string{key}
			limit := 1
			if key == "remote" {
				limit = 3
			}
			for len(d) <= limit && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				d = append(d, args[i])
			}
			directives = append(directives, d)
		}
	}
	proto, port := "udp", "1194"
	for _, d := range directives {
		if len(d) != 2 {
			continue
		}
		switch d[0] {
		case "proto":
			proto = d[1]
		case "port", "rport":
			port = d[1]
		}
	}
	var out []Endpoint
	seen := map[string]bool{}
	for _, d := range directives {
		if d[0] != "remote" || len(d) < 2 || len(d) > 4 {
			continue
		}
		a, e := netip.ParseAddr(d[1])
		if e != nil || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
			continue
		}
		epPort, epProto := port, proto
		if len(d) > 2 {
			epPort = d[2]
		}
		if len(d) > 3 {
			epProto = d[3]
		}
		switch epProto {
		case "udp", "udp4", "udp6":
			epProto = "udp"
		case "tcp-client", "tcp4-client", "tcp6-client":
			epProto = "tcp"
		default:
			continue
		}
		p, e := strconv.Atoi(epPort)
		if e != nil || p < 1 || p > 65535 {
			continue
		}
		key := a.String() + "/" + epPort + "/" + epProto
		if !seen[key] {
			out = append(out, Endpoint{Address: a.String(), Port: p, Protocol: epProto})
			seen[key] = true
		}
		if len(out) > 64 {
			return nil
		}
	}
	return out
}

// Small data tokenizer: quotes and comments only; no shell expansion/escaping.
func metadataFields(s string) ([]string, bool) {
	var out []string
	var field strings.Builder
	var quote rune
	for _, c := range s {
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				field.WriteRune(c)
			}
			continue
		}
		if c == '#' || c == ';' {
			break
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			if field.Len() > 0 {
				out = append(out, field.String())
				field.Reset()
			}
		} else {
			field.WriteRune(c)
		}
	}
	if field.Len() > 0 {
		out = append(out, field.String())
	}
	return out, quote == 0
}
