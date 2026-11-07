package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"time"

	"vault443/internal/model"
)

const OutlineMark uint32 = 0x564c5404

type OutlineProcess struct {
	process        Process
	Port           int
	User, Password string
}

func (p *OutlineProcess) Prepare() error {
	if p.User != "" {
		return errors.New("Outline adapter already prepared")
	}
	var secret [48]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	p.User, p.Password = hex.EncodeToString(secret[:16]), hex.EncodeToString(secret[16:])
	return nil
}
func (p *OutlineProcess) Start(ctx context.Context, path string, c model.OutlineRuntime) error {
	if p.User == "" {
		return errors.New("Outline adapter is not prepared")
	}
	c.Username, c.Password = p.User, p.Password
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	cmd := exec.Command(path)
	cmd.Stdin = bytes.NewReader(data)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err = p.process.StartInstalled(ctx, cmd); err != nil {
		return err
	}
	ready := make(chan int, 1)
	go func() {
		var answer struct {
			Ready bool `json:"ready"`
			Port  int  `json:"port"`
		}
		if json.NewDecoder(stdout).Decode(&answer) == nil && answer.Ready && answer.Port > 0 && answer.Port <= 65535 {
			ready <- answer.Port
		} else {
			ready <- 0
		}
	}()
	select {
	case port := <-ready:
		if port != 0 {
			p.Port = port
			return nil
		}
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
	p.Stop(context.Background())
	return errors.New("Outline adapter did not become ready")
}
func (p *OutlineProcess) Alive() bool { return p.process.Alive() }
func (p *OutlineProcess) Stop(ctx context.Context) error {
	err := p.process.StopContext(ctx)
	p.Port = 0
	p.User = ""
	p.Password = ""
	return err
}
