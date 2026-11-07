package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestPrivateEOFProcess(t *testing.T) {
	if os.Getenv("VAULT443_TEST_PRIVATE_EOF") != "1" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	fmt.Print("private-stdin-closed")
	os.Exit(0)
}

func TestWaitContextPreservesProcessUntilPrivateEOF(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestPrivateEOFProcess$")
	cmd.Env = append(os.Environ(), "VAULT443_TEST_PRIVATE_EOF=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := Process{cmd: cmd, done: make(chan struct{})}
	var exitErr error
	go func() { exitErr = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.WaitContext(canceled); !errors.Is(err, context.Canceled) || !p.Alive() {
		t.Fatalf("canceled wait must leave the private engine reserved and alive: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	grace, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := p.WaitContext(grace); err != nil {
		t.Fatal(err)
	}
	if exitErr != nil || p.Alive() || output.String() != "private-stdin-closed" {
		t.Fatalf("private EOF did not produce a clean process exit: %v, %q", exitErr, output.String())
	}
}
