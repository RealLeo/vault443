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
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"vault443/internal/journal"
	"vault443/internal/securefs"
)

type Process struct {
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	job  windows.Handle
}

func checkInstalled(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("installed executable path must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return errors.New("installed executable unavailable")
		}
		if err = securefs.Check(info, p, 0, false); err != nil {
			return fmt.Errorf("installed executable path is unsafe: %w", err)
		}
		if p == path && !info.Mode().IsRegular() {
			return errors.New("installed executable is not a regular file")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}
func CheckBinary(path string) error { return CheckBinaryContext(context.Background(), path) }
func CheckBinaryContext(parent context.Context, path string) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if err := checkInstalled(path); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil || !strings.HasPrefix(string(b), "Xray "+Version+" ") {
		return fmt.Errorf("Xray %s is required", Version)
	}
	return nil
}
func WriteConfig(dir string, data []byte) (string, error) {
	path := filepath.Join(dir, "core.json")
	return path, securefs.Write(path, data)
}

// StartInstalled places every helper in a kill-on-close Job Object. The job
// handle is not inherited, so a supervisor crash cannot orphan a privileged core.
func (p *Process) StartInstalled(ctx context.Context, cmd *exec.Cmd) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkInstalled(cmd.Path); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil {
		return errors.New("installed process is already running")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return err
	}
	cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot"), "WINDIR=" + os.Getenv("WINDIR"), "PATH=" + filepath.Dir(cmd.Path) + `;` + filepath.Join(os.Getenv("SystemRoot"), "System32")}
	if err = cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		windows.CloseHandle(job)
		return err
	}
	p.cmd, p.done, p.job = cmd, make(chan struct{}), job
	done := p.done
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.err = err
		if p.job == job {
			windows.CloseHandle(job)
			p.job = 0
		}
		p.mu.Unlock()
		close(done)
	}()
	return nil
}
func (p *Process) Start(ctx context.Context, path, config string, sessions ...*journal.Session) error {
	if err := CheckBinaryContext(ctx, path); err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(checkCtx, path, "run", "-test", "-config", config).Run(); err != nil {
		return errors.New("Xray rejected the generated configuration")
	}
	var session *journal.Session
	if len(sessions) > 0 {
		session = sessions[0]
	}
	output := newOutputWriter(session)
	cmd := exec.Command(path, "run", "-config", config)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := p.StartInstalled(ctx, cmd); err != nil {
		return err
	}
	go func() { p.mu.Lock(); done := p.done; p.mu.Unlock(); <-done; output.Flush() }()
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

// WaitContext waits for confirmed process termination without sending a signal
// or closing its Job Object. A caller can first request a helper-specific clean
// shutdown, then fall back to StopContext when its grace period expires. Like
// StopContext, it reports termination rather than the child's exit status.
func (p *Process) WaitContext(ctx context.Context) error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.mu.Unlock()
	if cmd == nil {
		return nil
	}
	select {
	case <-done:
	default:
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	p.mu.Lock()
	if p.cmd == cmd {
		p.cmd = nil
	}
	p.mu.Unlock()
	return nil
}

func (p *Process) Stop() error { return p.StopContext(context.Background()) }
func (p *Process) StopContext(ctx context.Context) error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.mu.Unlock()
	if cmd == nil {
		return nil
	}
	cmd.Process.Kill()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.mu.Lock()
	if p.cmd == cmd {
		p.cmd = nil
	}
	p.mu.Unlock()
	return nil
}
