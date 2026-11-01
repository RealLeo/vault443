package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"vault443/internal/model"
)

// OutlineMark is confined to the private SOCKS adapter. It never selects a
// physical route or grants an Internet exception.
const OutlineMark uint32 = 0x564c5404

type OutlineProcess struct {
	process        Process
	TCP            *net.TCPListener
	UDP            *net.UDPConn
	Port           int
	User, Password string
}

func (p *OutlineProcess) Prepare() error {
	if p.TCP != nil {
		return errors.New("Outline adapter already prepared")
	}
	tcp, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return errors.New("cannot reserve private Outline TCP port")
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if e != nil {
		tcp.Close()
		return errors.New("cannot reserve private Outline UDP port")
	}
	var secret [48]byte
	if _, e = rand.Read(secret[:]); e != nil {
		tcp.Close()
		udp.Close()
		return errors.New("cannot create Outline session credentials")
	}
	p.TCP, p.UDP, p.Port = tcp, udp, port
	p.User, p.Password = hex.EncodeToString(secret[:16]), hex.EncodeToString(secret[16:])
	return nil
}

func (p *OutlineProcess) Start(ctx context.Context, path string, c model.OutlineRuntime) error {
	if p.TCP == nil || p.UDP == nil {
		return errors.New("Outline listener is not prepared")
	}
	// This helper is selected by the package, never by an imported document.
	if !filepath.IsAbs(path) {
		return errors.New("Outline executable path must be absolute")
	}
	for part := path; part != "/"; part = filepath.Dir(part) {
		info, e := os.Lstat(part)
		if e != nil {
			return errors.New("installed Outline adapter unavailable")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Outline executable must be root-owned and not writable by other users")
		}
	}
	c.Username, c.Password = p.User, p.Password
	data, e := json.Marshal(c)
	if e != nil {
		return errors.New("invalid Outline runtime configuration")
	}
	tf, e := p.TCP.File()
	if e != nil {
		return e
	}
	defer tf.Close()
	uf, e := p.UDP.File()
	if e != nil {
		return e
	}
	defer uf.Close()
	cmd := exec.Command(path)
	cmd.Stdin = bytes.NewReader(data)
	cmd.ExtraFiles = []*os.File{tf, uf}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return errors.New("cannot create private Outline readiness pipe")
	}
	// Errors from third-party transports must never reach unredacted journals.
	if e = cmd.Start(); e != nil {
		return errors.New("cannot start Outline adapter")
	}
	p.process.mu.Lock()
	p.process.cmd = cmd
	p.process.done = make(chan struct{})
	done := p.process.done
	p.process.mu.Unlock()
	ready := make(chan bool, 1)
	go func() {
		var v struct {
			Ready bool `json:"ready"`
		}
		e := json.NewDecoder(stdout).Decode(&v)
		ready <- e == nil && v.Ready
	}()
	go func() { e := cmd.Wait(); p.process.mu.Lock(); p.process.err = e; p.process.mu.Unlock(); close(done) }()
	select {
	case ok := <-ready:
		if ok {
			return nil
		}
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
	_ = p.Stop(context.Background())
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("Outline adapter did not become ready")
}
func (p *OutlineProcess) Alive() bool { return p.process.Alive() }
func (p *OutlineProcess) Stop(ctx context.Context) error {
	e := p.process.StopContext(ctx)
	if p.TCP != nil {
		p.TCP.Close()
		p.TCP = nil
	}
	if p.UDP != nil {
		p.UDP.Close()
		p.UDP = nil
	}
	p.Port = 0
	p.User = ""
	p.Password = ""
	return e
}
