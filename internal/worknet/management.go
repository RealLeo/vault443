package worknet

import (
	"errors"
	"strconv"
	"strings"
)

// OpenVPN 2.6's route-noexec suppresses redirect_gateway in hook environment
// (upstream init.c:do_route). This adapter reads ONLY redirect flags from the
// authenticated management socket's exact PUSH_REPLY notification. Actual
// routes, addresses and DNS remain exclusively supplied by the fixed helper.
// The raw notification may contain auth-token and must never be journaled.
func pushedRedirect(line string) (found, v4, v6 bool, err error) {
	if !strings.HasPrefix(line, ">LOG:") {
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(line, ">LOG:"), ",", 3)
	if len(parts) != 3 {
		return
	}
	if _, e := strconv.ParseInt(parts[0], 10, 64); e != nil {
		return
	}
	const prefix = "PUSH: Received control message: 'PUSH_REPLY"
	msg := parts[2]
	if !strings.HasPrefix(msg, prefix) {
		return
	}
	if !strings.HasSuffix(msg, "'") {
		err = errors.New("invalid OpenVPN pushed policy notification")
		return
	}
	body := strings.TrimSuffix(strings.TrimPrefix(msg, prefix), "'")
	if body == "" {
		return
	}
	if body[0] != ',' {
		err = errors.New("invalid OpenVPN pushed policy notification")
		return
	}
	var fields []string
	var field strings.Builder
	escaped := false
	for _, c := range body[1:] {
		if c == '\n' || c == '\r' || c == 0 {
			err = errors.New("invalid OpenVPN pushed policy notification")
			return
		}
		if escaped {
			field.WriteRune(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == ',' {
			fields = append(fields, field.String())
			field.Reset()
		} else {
			field.WriteRune(c)
		}
	}
	if escaped {
		err = errors.New("invalid OpenVPN pushed policy notification")
		return
	}
	fields = append(fields, field.String())
	if len(fields) > 512 {
		err = errors.New("too many pushed OpenVPN options")
		return
	}
	for _, f := range fields {
		w := strings.Fields(f)
		if len(w) == 0 {
			err = errors.New("empty pushed OpenVPN option")
			return
		}
		if w[0] != "redirect-gateway" {
			continue
		}
		if found {
			err = errors.New("duplicate pushed Internet routing policy")
			return
		}
		found = true
		v4, v6, err = redirectFlags(w[1:])
		if err != nil {
			return
		}
	}
	return
}
func redirectFlags(flags []string) (v4, v6 bool, err error) {
	v4 = true
	for _, f := range flags {
		switch f {
		case "def1", "local", "autolocal", "bypass-dhcp":
		case "ipv6":
			v6 = true
		case "!ipv4":
			v4 = false
		default:
			return false, false, errors.New("unsupported OpenVPN Internet routing flag")
		}
	}
	return
}
func sensitiveOpenVPNLine(line string) bool {
	s := strings.ToLower(line)
	for _, part := range []string{"push_reply", "push_continuation", "auth-token", "auth_token", ">password:", "password =", "vault443_event_token"} {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}
