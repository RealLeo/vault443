package ipc

import (
	"errors"
	"os/user"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"vault443/internal/service"
)

// IdentitySource is deliberately independent of caller-supplied method arguments.
// SystemIdentity obtains the UID only from the authenticated D-Bus peer.
type IdentitySource interface {
	UID(dbus.Sender) (uint32, error)
	Groups(uint32) ([]string, error)
	LocalActive(uint32) (bool, error)
}
type Authorizer struct {
	Source        IdentitySource
	OperatorGroup string
}

func (a Authorizer) Authorize(sender dbus.Sender) (service.Caller, error) {
	var c service.Caller
	if !strings.HasPrefix(string(sender), ":") {
		return c, errors.New("a unique authenticated D-Bus sender is required")
	}
	uid, err := a.Source.UID(sender)
	if err != nil {
		return c, errors.New("cannot authenticate the caller")
	}
	groups, err := a.Source.Groups(uid)
	if err != nil {
		return c, errors.New("cannot resolve caller group membership")
	}
	operator := false
	admin := false
	for _, g := range groups {
		if g == a.OperatorGroup {
			operator = true
		}
		if g == "sudo" || g == "admin" || g == "wheel" {
			admin = true
		}
	}
	if !operator {
		return c, errors.New("caller must belong to the vault443 operator group")
	}
	active, err := a.Source.LocalActive(uid)
	if err != nil || !active {
		return c, errors.New("an active local login session is required")
	}
	return service.Caller{UID: uid, Admin: admin || uid == 0}, nil
}

type SystemIdentity struct{ Conn *dbus.Conn }

func (s SystemIdentity) UID(sender dbus.Sender) (uint32, error) {
	var uid uint32
	err := s.Conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid)
	return uid, err
}
func (s SystemIdentity) Groups(uid uint32) ([]string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, id := range ids {
		g, e := user.LookupGroupId(id)
		if e != nil {
			return nil, e
		}
		out = append(out, g.Name)
	}
	return out, nil
}

type loginSession struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

func (s SystemIdentity) LocalActive(uid uint32) (bool, error) {
	var sessions []loginSession
	err := s.Conn.Object("org.freedesktop.login1", "/org/freedesktop/login1").Call("org.freedesktop.login1.Manager.ListSessions", 0).Store(&sessions)
	if err != nil {
		return false, err
	}
	for _, sess := range sessions {
		if sess.UID != uid {
			continue
		}
		var props map[string]dbus.Variant
		if err := s.Conn.Object("org.freedesktop.login1", sess.Path).Call("org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.login1.Session").Store(&props); err != nil {
			return false, err
		}
		active, aok := props["Active"].Value().(bool)
		remote, rok := props["Remote"].Value().(bool)
		kind, kok := props["Type"].Value().(string)
		class, cok := props["Class"].Value().(string)
		if aok && rok && kok && cok && active && !remote && class == "user" && (kind == "x11" || kind == "wayland" || kind == "tty") {
			return true, nil
		}
	}
	return false, nil
}
