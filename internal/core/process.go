package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"vault443/internal/journal"
)

type Process struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// CheckBinary rejects user-replaceable cores and symlinks. Version pinning is
// intentional: the TUN schema is not stable across arbitrary Xray releases.
func CheckBinary(path string) error { return CheckBinaryContext(context.Background(), path) }

func CheckBinaryContext(parent context.Context, path string) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("core path must be absolute")
	}
	for p := path; p != "/"; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return errors.New("installed core is unavailable")
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode()&022 != 0 || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("core path must be root-owned and not writable by other users")
		}
		if p == path && (!fi.Mode().IsRegular() || fi.Mode()&0111 == 0) {
			return errors.New("core is not executable")
		}
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, path, "version").Output()
	if parent.Err() != nil {
		return parent.Err()
	}
	if err != nil || !strings.HasPrefix(string(b), "Xray "+Version+" ") {
		return fmt.Errorf("Xray %s is required", Version)
	}
	return nil
}

func WriteConfig(dir string, b []byte) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", errors.New("runtime directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0077 != 0 {
		return "", errors.New("runtime directory must be private")
	}
	f, err := os.CreateTemp(dir, ".core-*.json")
	if err != nil {
		return "", err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "core.json")
	if err = os.Rename(name, path); err != nil {
		return "", err
	}
	return path, nil
}

func (p *Process) Start(ctx context.Context, path, config string, sessions ...*journal.Session) error {
	var session *journal.Session
	if len(sessions) > 0 {
		session = sessions[0]
	}
	if err := CheckBinaryContext(ctx, path); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		session.Log("error", "Xray verification: "+err.Error())
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	check := exec.CommandContext(checkCtx, path, "run", "-test", "-config", config)
	checkOutput := newOutputWriter(session)
	check.Stdout, check.Stderr = checkOutput, checkOutput
	checkErr := check.Run()
	checkOutput.Flush()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if checkErr != nil {
		session.Log("error", "Xray rejected the generated configuration")
		return errors.New("Xray rejected the generated configuration")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.cmd != nil {
		return errors.New("core is already running")
	}
	// Not CommandContext: a D-Bus request timeout must not kill the system VPN.
	cmd := exec.Command(path, "run", "-config", config)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output := newOutputWriter(session)
	cmd.Stdout, cmd.Stderr = output, output
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		session.Log("error", "Cannot start installed Xray core")
		return errors.New("cannot start installed core")
	}
	p.cmd, p.done, p.err = cmd, make(chan struct{}), nil
	done := p.done
	session.Log("info", "Xray process started")
	go func() {
		err := cmd.Wait()
		output.Flush()
		if err != nil {
			session.Log("warning", "Xray process stopped: "+err.Error())
		} else {
			session.Log("info", "Xray process stopped")
		}
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(done)
	}()
	return nil
}

func (p *Process) Alive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *Process) Stop() error { return p.StopContext(context.Background()) }

func (p *Process) StopContext(ctx context.Context) error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	if cmd == nil {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
	}
	p.mu.Lock()
	if p.cmd == cmd {
		p.cmd = nil
	}
	p.mu.Unlock()
	return nil
}
