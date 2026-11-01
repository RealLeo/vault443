package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func (s *Store) backupLegacy(raw []byte) error {
	path := filepath.Join(s.dir, "state.v2.backup.json")
	f, e := os.CreateTemp(s.dir, ".state-backup-*")
	if e != nil {
		return errors.New("cannot create private profile migration backup")
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
		return errors.New("cannot persist profile migration backup")
	}
	// link publishes a complete durable file without overwriting a previous
	// backup. A crash before publication leaves only an ignored temporary file.
	e = os.Link(tmp, path)
	if os.IsExist(e) {
		old, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errors.New("cannot verify existing profile migration backup")
		}
		defer old.Close()
		fi, err := old.Stat()
		if err != nil || secureInfo(fi, s.owner, false) != nil || fi.Size() > 16<<20 {
			return errors.New("invalid profile migration backup")
		}
		data, err := io.ReadAll(io.LimitReader(old, 16<<20+1))
		if err != nil || !bytes.Equal(data, raw) {
			return errors.New("profile migration backup conflicts with current legacy data; refusing to overwrite")
		}
	} else if e != nil {
		return errors.New("cannot publish profile migration backup")
	}
	d, e := os.Open(s.dir)
	if e != nil {
		return errors.New("cannot sync profile migration backup")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("cannot sync profile migration backup")
	}
	return nil
}
