package securefs

import (
	"errors"
	"os"
	"path/filepath"
)

// Write publishes only a complete, flushed document under a private directory.
func Write(path string, data []byte) error {
	if !filepath.IsAbs(path) {
		return errors.New("private document path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := MkdirAll(dir, 0700); err != nil {
		return err
	}
	owner, err := Owner(true)
	if err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if err = Check(info, dir, owner, true); err != nil {
		return err
	}
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() {
			return errors.New("private document is not a regular file")
		}
		if err = Check(info, path, owner, true); err != nil {
			return err
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, err := os.CreateTemp(dir, ".atomic-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = Replace(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return SyncDir(d)
}
