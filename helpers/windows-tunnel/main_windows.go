// Fixed private engine host. The LocalSystem supervisor supplies validated
// configuration and updates over inherited stdin; there is no public IPC.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type engine interface {
	IpcSet(string) error
	IpcGet() (string, error)
	Up() error
	Close()
	Wait() chan struct{}
}
type interfaceBind interface {
	BindSocketToInterface4(uint32, bool) error
	BindSocketToInterface6(uint32, bool) error
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Private tunnel engine stopped")
		os.Exit(1)
	}
}
func run() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 65536), 2<<20)
	if !scanner.Scan() {
		return errors.New("missing private configuration")
	}
	var c config
	if err := decodeFrame(scanner.Bytes(), &c); err != nil {
		return err
	}
	if !regexp.MustCompile(`^v443w[0-9a-f]{8}$`).MatchString(c.Interface) || c.MTU < 576 || c.MTU > 65535 || len(c.UAPI) > 1<<20 {
		return errors.New("invalid private configuration")
	}
	guid, err := windows.GUIDFromString(c.GUID)
	if err != nil {
		return errors.New("invalid private adapter identity")
	}
	var e engine
	var bind interfaceBind
	switch c.Kind {
	case "wireguard":
		// Match the creator-owned Wintun identity checked by the supervisor.
		tun.WintunTunnelType = "Wintun"
		t, err := tun.CreateTUNWithRequestedGUID(c.Interface, &guid, c.MTU)
		if err != nil {
			return err
		}
		b := conn.NewDefaultBind()
		bind = b.(interfaceBind)
		e = device.NewDevice(t, b, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
	case "amneziawg":
		awgtun.WintunTunnelType = "Wintun"
		t, err := awgtun.CreateTUNWithRequestedGUID(c.Interface, &guid, c.MTU)
		if err != nil {
			return err
		}
		b := awgconn.NewDefaultBind()
		bind = b.(interfaceBind)
		e = awgdevice.NewDevice(t, b, &awgdevice.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
	default:
		return errors.New("invalid private engine")
	}
	defer e.Close()
	if err := e.IpcSet(c.UAPI); err != nil {
		return err
	}
	if err := e.Up(); err != nil {
		return err
	}
	if err := bindInterfaces(bind, c.Bind4, c.Bind6); err != nil {
		return err
	}
	commands := make(chan command, 8)
	readErrors := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			var cmd command
			if err := decodeFrame(scanner.Bytes(), &cmd); err != nil {
				readErrors <- err
				return
			}
			if len(cmd.UAPI) > 1<<20 || len(cmd.Probe) > 32 {
				readErrors <- errors.New("private update exceeds limits")
				return
			}
			commands <- cmd
		}
		if err := scanner.Err(); err != nil {
			readErrors <- err
		} else {
			readErrors <- io.EOF
		}
	}()
	encoder := json.NewEncoder(os.Stdout)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	observe := func() error {
		data, err := e.IpcGet()
		if err != nil {
			return err
		}
		out, err := observation(data)
		if err != nil {
			return err
		}
		return encoder.Encode(out)
	}
	if err := observe(); err != nil {
		return err
	}
	for {
		select {
		case cmd := <-commands:
			if cmd.UAPI != "" {
				if err := e.IpcSet(cmd.UAPI); err != nil {
					return err
				}
			}
			if cmd.Bind4 != nil {
				c.Bind4 = *cmd.Bind4
			}
			if cmd.Bind6 != nil {
				c.Bind6 = *cmd.Bind6
			}
			if cmd.Bind4 != nil || cmd.Bind6 != nil {
				if err := bindInterfaces(bind, c.Bind4, c.Bind6); err != nil {
					return err
				}
			}
			for _, key := range cmd.Probe {
				if err := probePeer(e, key); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := observe(); err != nil {
				return err
			}
		case err := <-readErrors:
			return err
		case <-e.Wait():
			return errors.New("tunnel engine stopped")
		}
	}
}
func bindInterfaces(bind interfaceBind, v4, v6 uint32) error {
	if err := bind.BindSocketToInterface4(v4, v4 == 0); err != nil && v4 != 0 {
		return err
	}
	if err := bind.BindSocketToInterface6(v6, v6 == 0); err != nil && v6 != 0 {
		return err
	}
	return nil
}
func probePeer(e engine, key string) error {
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return errors.New("invalid peer probe identity")
	}
	switch d := e.(type) {
	case *device.Device:
		var public device.NoisePublicKey
		copy(public[:], raw)
		p := d.LookupPeer(public)
		if p == nil {
			return errors.New("unknown probe peer")
		}
		// An unavailable peer must not terminate healthy peers in this device.
		// The supervisor observes authentication and applies the peer timeout.
		_ = p.SendHandshakeInitiation(false)
		return nil
	case *awgdevice.Device:
		var public awgdevice.NoisePublicKey
		copy(public[:], raw)
		p := d.LookupPeer(public)
		if p == nil {
			return errors.New("unknown probe peer")
		}
		_ = p.SendHandshakeInitiation(false)
		return nil
	}
	return errors.New("invalid private engine")
}
