// Package store keeps all privileged persistent state in one atomic root-owned
// document. Callers cannot choose file paths, and no profile files live in $HOME.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"vault443/internal/model"
)

type Subscription struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	UpdatedAt   int64  `json:"updatedAt"`
	LastAttempt int64  `json:"lastAttempt"`
	LastError   string `json:"lastError,omitempty"`
}
type User struct {
	Profiles      []model.Profile `json:"profiles"`
	Subscriptions []Subscription  `json:"subscriptions"`
}
type Session struct {
	UID       uint32 `json:"uid"`
	ProfileID string `json:"profileId"`
}
type State struct {
	Version int             `json:"version"`
	Users   map[string]User `json:"users"`
	Boot    *Session        `json:"boot,omitempty"`
	Desired *Session        `json:"desired,omitempty"`
	BootID  string          `json:"bootId,omitempty"`
}

func UserKey(uid uint32) string             { return strconv.FormatUint(uint64(uid), 10) }
func (s State) User(uid uint32) User        { return s.Users[UserKey(uid)] }
func (s *State) SetUser(uid uint32, u User) { s.Users[UserKey(uid)] = u }
func (s *State) Profile(session *Session) (model.Profile, bool) {
	if session == nil {
		return model.Profile{}, false
	}
	for _, p := range s.User(session.UID).Profiles {
		if p.ID == session.ProfileID {
			return p, true
		}
	}
	return model.Profile{}, false
}

type Store struct {
	mu    sync.Mutex
	dir   string
	state State
	owner int
	lock  *os.File
}

// OpenExclusive serializes the daemon and root maintenance commands. A second
// process cannot race a running service's in-memory copy of the state document.
func OpenExclusive(dir string, allowUnprivileged bool) (*Store, error) {
	s, err := Open(dir, allowUnprivileged)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, "daemon.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open daemon state lock")
	}
	info, err := f.Stat()
	if err == nil {
		err = secureInfo(info, s.owner, false)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("daemon is already running; stop it before root maintenance")
	}
	// Reload after acquiring the lock; the previous owner may have saved between
	// the first read and releasing its lock.
	s, err = Open(dir, allowUnprivileged)
	if err != nil {
		f.Close()
		return nil, err
	}
	s.lock = f
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		err := s.lock.Close()
		s.lock = nil
		return err
	}
	return nil
}

func Open(dir string, allowUnprivileged bool) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("state directory must be absolute")
	}
	owner := 0
	if allowUnprivileged {
		owner = os.Geteuid()
	} else if os.Geteuid() != 0 {
		return nil, errors.New("the system daemon must run as root")
	}
	// Check all existing ancestors before creating any child: do not follow a
	// writable symlink supplied in a custom --state-dir.
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("state path must not contain symlinks or non-directories")
			}
			if !allowUnprivileged {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
					return nil, errors.New("system state ancestors must be root-owned and not group/world-writable")
				}
			}
			if p == filepath.Clean(dir) {
				if e = secureInfo(info, owner, true); e != nil {
					return nil, e
				}
			}
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if err = secureInfo(info, owner, true); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, owner: owner, state: State{Version: 2, Users: map[string]User{}}}
	path := filepath.Join(dir, "state.json")
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, errors.New("cannot open protected state")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if err = secureInfo(info, owner, false); err != nil {
		return nil, err
	}
	if info.Size() > 16<<20 {
		return nil, errors.New("state exceeds size limit")
	}
	original, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return nil, errors.New("cannot read protected state")
	}
	d := json.NewDecoder(bytes.NewReader(original))
	d.DisallowUnknownFields()
	if err = d.Decode(&s.state); err != nil {
		return nil, errors.New("invalid state document; refusing to overwrite")
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid trailing state data")
	}
	if s.state.Version != 2 || s.state.Users == nil {
		return nil, errors.New("unsupported state version")
	}
	if _, ok := s.state.Profile(s.state.Boot); s.state.Boot != nil && !ok {
		return nil, errors.New("boot profile is missing")
	}
	if _, ok := s.state.Profile(s.state.Desired); s.state.Desired != nil && !ok {
		return nil, errors.New("desired profile is missing")
	}
	return s, nil
}

func secureInfo(info os.FileInfo, owner int, dir bool) error {
	if info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return errors.New("state path has incorrect file type")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != owner {
		return errors.New("state must be owned by the daemon user")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("state permissions must exclude group and other users")
	}
	return nil
}
func clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}
func (s *Store) Snapshot() State { s.mu.Lock(); defer s.mu.Unlock(); return clone(s.state) }
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.save(next); err != nil {
		return err
	}
	s.state = next
	return nil
}
func (s *Store) save(next State) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > 16<<20 {
		return errors.New("state exceeds size limit")
	}
	f, err := os.CreateTemp(s.dir, ".state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(s.dir, "state.json")); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("state saved but directory sync failed: %w", err)
	}
	defer d.Close()
	return d.Sync()
}
