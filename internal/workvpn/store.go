package workvpn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Store shares the daemon's already exclusively locked state directory with the
// VLESS store, but never reads or rewrites the VLESS schema-v2 document.
type Store struct {
	mu    sync.Mutex
	dir   string
	owner int
	state State
}

func Open(dir string, allowUnprivileged ...bool) (*Store, error) {
	testing := len(allowUnprivileged) > 0 && allowUnprivileged[0]
	owner := 0
	if testing {
		owner = os.Geteuid()
	} else if os.Geteuid() != 0 {
		return nil, errors.New("the system daemon must run as root")
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("work VPN state directory must be absolute")
	}
	dir = filepath.Clean(dir)
	for p := dir; ; p = filepath.Dir(p) {
		fi, e := os.Lstat(p)
		if e == nil {
			if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("work VPN state path must contain directories without symlinks")
			}
			if !testing {
				st, ok := fi.Sys().(*syscall.Stat_t)
				if !ok || st.Uid != 0 || fi.Mode().Perm()&0022 != 0 {
					return nil, errors.New("work VPN state ancestors must be root-owned and not writable by other users")
				}
			}
			if p == dir {
				if e = secureInfo(fi, owner, true); e != nil {
					return nil, e
				}
			}
		} else if !os.IsNotExist(e) {
			return nil, errors.New("cannot inspect work VPN state path")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, errors.New("cannot create private work VPN state directory")
	}
	fi, e := os.Lstat(dir)
	if e != nil {
		return nil, errors.New("cannot inspect work VPN state directory")
	}
	if e = secureInfo(fi, owner, true); e != nil {
		return nil, e
	}
	s := &Store{dir: dir, owner: owner, state: State{Version: 2, Users: map[string]WorkUser{}}}
	f, e := os.OpenFile(filepath.Join(dir, StoreFilename), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e != nil {
		return nil, errors.New("cannot open protected work VPN state")
	}
	defer f.Close()
	fi, e = f.Stat()
	if e != nil {
		return nil, errors.New("cannot inspect work VPN state")
	}
	if e = secureInfo(fi, owner, false); e != nil {
		return nil, e
	}
	if fi.Size() > MaxStateBytes {
		return nil, errors.New("work VPN state exceeds size limit")
	}
	raw, e := io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	if e != nil || len(raw) > MaxStateBytes {
		return nil, errors.New("cannot read bounded work VPN state")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&s.state); e != nil {
		return nil, errors.New("invalid work VPN state; refusing to overwrite")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid trailing work VPN state data")
	}
	legacy := s.state.Version == 1
	if legacy {
		for key, user := range s.state.Users {
			for i := range user.Profiles {
				if user.Profiles[i].Protocol() != "openvpn" || user.Profiles[i].WireGuard != nil {
					return nil, errors.New("invalid legacy work VPN state; refusing to migrate")
				}
				user.Profiles[i].Kind = "openvpn"
			}
			s.state.Users[key] = user
		}
		s.state.Version = 2
	}
	if e = validateState(s.state); e != nil {
		return nil, e
	}
	if legacy {
		if e = s.backupLegacy(raw); e != nil {
			return nil, e
		}
		if e = s.Update(func(*State) error { return nil }); e != nil {
			return nil, e
		}
	}
	return s, nil
}

func (s *Store) backupLegacy(raw []byte) error {
	path := filepath.Join(s.dir, "work-vpn.v1.backup.json")
	f, e := os.CreateTemp(s.dir, ".work-vpn-backup-*")
	if e != nil {
		return errors.New("cannot create private work VPN migration backup")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("cannot persist work VPN migration backup")
	}
	// link publishes a complete durable file without overwriting a previous
	// backup. A crash before publication leaves only an ignored temporary file.
	e = os.Link(tmp, path)
	if os.IsExist(e) {
		old, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("cannot verify existing work VPN migration backup")
		}
		defer old.Close()
		fi, err := old.Stat()
		if err != nil || secureInfo(fi, s.owner, false) != nil || fi.Size() > MaxStateBytes {
			return errors.New("invalid work VPN migration backup")
		}
		data, err := io.ReadAll(io.LimitReader(old, MaxStateBytes+1))
		if err != nil || !bytes.Equal(data, raw) {
			return errors.New("work VPN migration backup conflicts with current legacy data; refusing to overwrite")
		}
	} else if e != nil {
		return errors.New("cannot publish work VPN migration backup")
	}
	d, e := os.Open(s.dir)
	if e != nil {
		return errors.New("cannot sync work VPN migration backup")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("cannot sync work VPN migration backup")
	}
	return nil
}

func secureInfo(fi os.FileInfo, owner int, dir bool) error {
	if fi.IsDir() != dir || (!dir && !fi.Mode().IsRegular()) {
		return errors.New("work VPN state has incorrect file type")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != owner || fi.Mode().Perm()&0077 != 0 {
		return errors.New("work VPN state must be private and owned by the daemon user")
	}
	return nil
}
func clone(s State) State        { b, _ := json.Marshal(s); var o State; _ = json.Unmarshal(b, &o); return o }
func (s *Store) Snapshot() State { s.mu.Lock(); defer s.mu.Unlock(); return clone(s.state) }
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.state)
	if e := fn(&next); e != nil {
		return e
	}
	if e := validateState(next); e != nil {
		return e
	}
	b, e := json.MarshalIndent(next, "", "  ")
	if e != nil || len(b) > MaxStateBytes {
		return errors.New("work VPN state exceeds size limit")
	}
	// A private directory protects rename; recheck the target so accidental
	// permission changes or symlinks are rejected rather than silently repaired.
	if fi, e := os.Lstat(s.dir); e != nil {
		return errors.New("cannot inspect work VPN state directory")
	} else if e = secureInfo(fi, s.owner, true); e != nil {
		return e
	}
	path := filepath.Join(s.dir, StoreFilename)
	if fi, e := os.Lstat(path); e == nil {
		if e = secureInfo(fi, s.owner, false); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return errors.New("cannot inspect protected work VPN state")
	}
	f, e := os.CreateTemp(s.dir, ".work-vpn-*")
	if e != nil {
		return errors.New("cannot create private work VPN state update")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("cannot save private work VPN state")
	}
	if e = os.Rename(tmp, path); e != nil {
		return errors.New("cannot replace private work VPN state")
	}
	// Publish the durable document after rename even if fsync fails; continuing
	// with the old memory snapshot could erase the update on the next write.
	s.state = next
	d, e := os.Open(s.dir)
	if e != nil {
		return errors.New("work VPN state saved but directory sync failed")
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return errors.New("work VPN state saved but directory sync failed")
	}
	return nil
}

func validateState(s State) error {
	if s.Version != 2 || s.Users == nil {
		return errors.New("unsupported work VPN state version; refusing to overwrite")
	}
	if len(s.Users) > 1024 || len(s.Desired) > 64 || len(s.BootID) > 128 || strings.ContainsAny(s.BootID, "\x00\r\n") {
		return errors.New("invalid work VPN state limits")
	}
	for key, u := range s.Users {
		n, e := strconv.ParseUint(key, 10, 32)
		if e != nil || UserKey(uint32(n)) != key {
			return errors.New("invalid work VPN state owner")
		}
		if len(u.Profiles) > MaxProfiles || len(u.Rules) > 1024 || len(u.DNSRules) > 256 {
			return errors.New("work VPN library exceeds limits")
		}
		ids := map[string]bool{}
		for _, p := range u.Profiles {
			if ids[p.ID] {
				return errors.New("duplicate OpenVPN profile")
			}
			if e := ValidateProfile(p); e != nil {
				return errors.New("invalid stored OpenVPN profile; refusing to overwrite")
			}
			ids[p.ID] = true
		}
		seen := map[string]bool{}
		for _, r := range u.Rules {
			q, e := NewRouteRule(r.CIDR, r.Target)
			if e != nil || q.ID != r.ID || q.CIDR != r.CIDR || (r.Target != "local" && !ids[r.Target]) || seen[r.CIDR] {
				return errors.New("invalid or duplicate work VPN route rule")
			}
			if r.Target != "local" {
				p, _ := s.Profile(uint32(n), r.Target)
				if !p.AllowsPrefix(r.CIDR) {
					return errors.New("work route is outside the profile's AllowedIPs")
				}
			}
			seen[r.CIDR] = true
		}
		seen = map[string]bool{}
		for _, r := range u.DNSRules {
			q, e := NewDNSRule(r.Domain, r.Target)
			if e != nil || q.ID != r.ID || q.Domain != r.Domain || !ids[r.Target] || seen[r.Domain] {
				return errors.New("invalid or duplicate work VPN DNS rule")
			}
			p, _ := s.Profile(uint32(n), r.Target)
			if p.WireGuard != nil && len(p.WireGuard.DNSServers) == 0 {
				return errors.New("WireGuard profile has no DNS servers")
			}
			seen[r.Domain] = true
		}
	}
	seen := map[string]bool{}
	var owner *uint32
	for _, d := range s.Desired {
		if _, ok := s.Profile(d.UID, d.ProfileID); !ok || seen[d.ProfileID] {
			return errors.New("invalid desired OpenVPN profile")
		}
		seen[d.ProfileID] = true
		if owner != nil && *owner != d.UID {
			return errors.New("active work VPN profiles must have one owner")
		}
		uid := d.UID
		owner = &uid
	}
	return nil
}

// NewRouteRule accepts a host address or canonical CIDR. Its ID depends only on
// the destination so choosing another target updates the existing rule.
func NewRouteRule(cidr, target string) (RouteRule, error) {
	if a, e := netip.ParseAddr(cidr); e == nil {
		cidr = netip.PrefixFrom(a, a.BitLen()).String()
	}
	p, e := netip.ParsePrefix(cidr)
	if e != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() || p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Addr().IsLinkLocalUnicast() {
		return RouteRule{}, errors.New("route rule requires a unicast IP address or CIDR")
	}
	// /0 is needed to explicitly select a competing full-tunnel provider. The
	// runtime separately refuses arbitrary physical routes for target=local.
	if target != "local" && !validID(target) {
		return RouteRule{}, errors.New("invalid work VPN route target")
	}
	cidr = p.Masked().String()
	return RouteRule{ruleID("route", cidr), cidr, target}, nil
}
func NormalizeDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "~")
	if domain == "." {
		return ".", nil
	}
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return "", errors.New("invalid DNS routing domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS routing domain")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return "", errors.New("invalid DNS routing domain")
			}
		}
	}
	return domain, nil
}
func NewDNSRule(domain, target string) (DNSRule, error) {
	d, e := NormalizeDomain(domain)
	if e != nil {
		return DNSRule{}, e
	}
	if !validID(target) {
		return DNSRule{}, errors.New("invalid work VPN DNS target")
	}
	return DNSRule{ruleID("dns", d), d, target}, nil
}
func ruleID(kind, key string) string {
	s := sha256.Sum256([]byte(key))
	return kind + "-" + hex.EncodeToString(s[:12])
}
func validID(s string) bool {
	prefix, body, ok := strings.Cut(s, "-")
	if !ok || !oneOf(prefix, "ovpn", "wg", "awg") || len(body) != 32 {
		return false
	}
	_, e := hex.DecodeString(body)
	return e == nil
}
