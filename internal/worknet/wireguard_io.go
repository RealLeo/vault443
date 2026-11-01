package worknet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vault443/internal/network"
	"vault443/internal/workvpn"
)

type wgPeerObservation struct {
	Handshake int64
	RX, TX    uint64
	Endpoint  string
}

func peerID(key string) string { sum := sha256.Sum256([]byte(key)); return hex.EncodeToString(sum[:6]) }
func keyHex(key string) string {
	b, _ := base64.StdEncoding.DecodeString(key)
	return hex.EncodeToString(b)
}
func endpointString(e network.Endpoint) string {
	if e.Address == "" {
		return ""
	}
	return net.JoinHostPort(e.Address, strconv.Itoa(e.Port))
}

// Only this checked, root-owned executable is ever used; profile data cannot
// select a command or executable. Stderr can contain keys and is never returned.
func secureExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("VPN backend is not installed securely")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return errors.New("VPN backend must be root-owned")
	}
	return nil
}

func wireGuardConfig(w *workvpn.WireGuardConfig, endpoints []network.Endpoint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\nFwMark = %d\n", w.PrivateKey, w.ListenPort, network.OuterMark)
	for i, p := range w.Peers {
		fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if i < len(endpoints) && endpoints[i].Address != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", endpointString(endpoints[i]))
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		if p.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "PersistentKeepalive = %s\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

var awgUAPIKeys = map[string]string{
	"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition",
	"RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time",
	"KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts",
	"RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies",
}

func amneziaConfig(w *workvpn.WireGuardConfig, endpoints []network.Endpoint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "set=1\nprivate_key=%s\nlisten_port=%d\nfwmark=%d\n", keyHex(w.PrivateKey), w.ListenPort, network.OuterMark)
	var names []string
	for name := range w.Parameters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := awgUAPIKeys[name]
		if key == "" {
			key = strings.ToLower(name)
		}
		value := w.Parameters[name]
		if name == "HeaderProtectionKey" {
			value = keyHex(value)
		}
		if name == "RandomTrailers" || name == "DisableCookies" {
			if value == "true" {
				value = "1"
			} else {
				value = "0"
			}
		}
		fmt.Fprintf(&b, "%s=%s\n", key, value)
	}
	b.WriteString("replace_peers=true\n")
	for i, p := range w.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", keyHex(p.PublicKey))
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "preshared_key=%s\n", keyHex(p.PresharedKey))
		}
		if i < len(endpoints) && endpoints[i].Address != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", endpointString(endpoints[i]))
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
		}
		if p.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", p.PersistentKeepalive)
		}
	}
	b.WriteByte('\n')
	return b.String()
}

func runWG(ctx context.Context, path string, args []string, input string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	// wg accepts a path for setconf. An inherited descriptor keeps key material
	// out of argv and the filesystem; the generated text never reaches a shell.
	var pipe *os.File
	if input != "" {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, errors.New("cannot create private WireGuard configuration channel")
		}
		pipe = r
		defer r.Close()
		cmd.ExtraFiles = []*os.File{r}
		go func() { defer w.Close(); _, _ = io.Copy(w, strings.NewReader(input)) }()
	}
	_ = pipe
	var b limitedBuffer
	cmd.Stdout = &b
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("WireGuard control operation failed")
	}
	if b.exceeded {
		return nil, errors.New("WireGuard status exceeds size limit")
	}
	return b.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 2<<20 {
		limit := (2 << 20) - b.Len()
		if len(p) > limit {
			p = p[:limit]
			b.exceeded = true
		}
		_, _ = b.Buffer.Write(p)
	} else {
		b.exceeded = true
	}
	return n, nil
}

func readWireGuard(ctx context.Context, path, iface string, peers []workvpn.WireGuardPeer) (map[string]wgPeerObservation, error) {
	out := map[string]wgPeerObservation{}
	known := map[string]string{}
	for _, p := range peers {
		known[p.PublicKey] = peerID(p.PublicKey)
	}
	for _, field := range []string{"latest-handshakes", "transfer", "endpoints"} {
		b, err := runWG(ctx, path, []string{"show", iface, field}, "")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			id, ok := known[parts[0]]
			if !ok {
				return nil, errors.New("WireGuard peer identity changed unexpectedly")
			}
			v := out[id]
			switch field {
			case "latest-handshakes":
				v.Handshake, err = strconv.ParseInt(parts[1], 10, 64)
			case "transfer":
				if len(parts) != 3 {
					return nil, errors.New("invalid WireGuard traffic status")
				}
				v.RX, err = strconv.ParseUint(parts[1], 10, 64)
				if err == nil {
					v.TX, err = strconv.ParseUint(parts[2], 10, 64)
				}
			case "endpoints":
				if parts[1] != "(none)" {
					v.Endpoint = parts[1]
				}
			}
			if err != nil {
				return nil, errors.New("invalid WireGuard peer status")
			}
			out[id] = v
		}
	}
	if len(out) != len(peers) {
		return nil, errors.New("WireGuard peer set changed unexpectedly")
	}
	return out, nil
}

func amneziaRequest(ctx context.Context, path string, pid int, request string) ([]byte, error) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	c, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, errors.New("AmneziaWG control socket is unavailable")
	}
	defer c.Close()
	u, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("invalid AmneziaWG control transport")
	}
	peer, uid, err := peerPID(u)
	if err != nil || uid != 0 || peer != pid {
		return nil, errors.New("AmneziaWG control peer identity mismatch")
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if _, err = io.WriteString(c, request); err != nil {
		return nil, errors.New("AmneziaWG configuration write failed")
	}
	scanner := bufio.NewScanner(io.LimitReader(c, (2<<20)+1))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var result strings.Builder
	completed := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			completed = true
			break
		}
		if result.Len()+len(line) > 2<<20 {
			return nil, errors.New("AmneziaWG status exceeds size limit")
		}
		result.WriteString(line)
		result.WriteByte('\n')
	}
	if !completed || scanner.Err() != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("AmneziaWG control response timed out")
	}
	if !strings.HasSuffix(result.String(), "errno=0\n") {
		return nil, errors.New("AmneziaWG rejected its checked configuration")
	}
	return []byte(result.String()), nil
}

// UAPI get includes private key fields. Parse only the permitted status
// vocabulary, discard everything else, and never attach the raw response to an
// error, log or public snapshot.
func parseAmneziaStatus(data []byte, peers []workvpn.WireGuardPeer) (map[string]wgPeerObservation, error) {
	known := map[string]string{}
	for _, p := range peers {
		known[keyHex(p.PublicKey)] = peerID(p.PublicKey)
	}
	out := map[string]wgPeerObservation{}
	id := ""
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			var found bool
			id, found = known[value]
			if !found {
				return nil, errors.New("AmneziaWG peer identity changed unexpectedly")
			}
			out[id] = wgPeerObservation{}
			continue
		}
		if id == "" {
			continue
		}
		v := out[id]
		var err error
		switch key {
		case "last_handshake_time_sec":
			v.Handshake, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			v.RX, err = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			v.TX, err = strconv.ParseUint(value, 10, 64)
		case "endpoint":
			v.Endpoint = value
		default:
			continue
		}
		if err != nil {
			return nil, errors.New("invalid AmneziaWG peer status")
		}
		out[id] = v
	}
	if len(out) != len(peers) {
		return nil, errors.New("AmneziaWG peer set changed unexpectedly")
	}
	return out, nil
}
