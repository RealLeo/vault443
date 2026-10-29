package ipc

import (
	"context"
	"github.com/godbus/dbus/v5"
	"time"
)

func (a *API) PrepareOpenVPNImport(sender dbus.Sender, filesJSON string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.PrepareOpenVPNImport(c, filesJSON)
	return result(r, err)
}
func (a *API) CommitOpenVPNImport(sender dbus.Sender, draftID, iconsJSON string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.CommitOpenVPNImport(c, draftID, iconsJSON)
	return result(r, err)
}
func (a *API) CancelOpenVPNImport(sender dbus.Sender, draftID string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.CancelOpenVPNImport(c, draftID))
}
func (a *API) UpdateOpenVPNProfile(sender dbus.Sender, id, name, iconID string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.UpdateOpenVPNProfile(c, id, name, iconID))
}
func (a *API) RemoveOpenVPNProfile(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.RemoveOpenVPNProfile(c, id))
}
func (a *API) SetOpenVPNDebug(sender dbus.Sender, id string, enabled bool) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.SetOpenVPNDebug(c, id, enabled))
}
func (a *API) RequestOpenVPNConnect(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	id, err := a.service.RequestOpenVPNConnect(a.ctx, c, id)
	return result(map[string]string{"operationId": id}, err)
}
func (a *API) RequestOpenVPNDisconnect(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	id, err := a.service.RequestOpenVPNDisconnect(a.ctx, c, id)
	return result(map[string]string{"operationId": id}, err)
}
func (a *API) GetOpenVPNDiagnostics(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.GetOpenVPNDiagnostics(c, id)
	return result(r, err)
}
func (a *API) GetOpenVPNLogs(sender dbus.Sender, id, cursor string, limit int32) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.GetOpenVPNLogs(c, id, cursor, int(limit))
	return result(r, err)
}
func (a *API) ClearOpenVPNLogs(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.ClearOpenVPNLogs(c, id))
}
func (a *API) GetWorkRoutes(sender dbus.Sender) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.GetWorkRoutes(c)
	return result(r, err)
}
func (a *API) SetWorkRoute(sender dbus.Sender, cidr, target string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	defer cancel()
	return busError(a.service.SetWorkRoute(ctx, c, cidr, target))
}
func (a *API) RemoveWorkRoute(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	defer cancel()
	return busError(a.service.RemoveWorkRoute(ctx, c, id))
}
func (a *API) SetWorkDNS(sender dbus.Sender, domain, target string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	defer cancel()
	return busError(a.service.SetWorkDNS(ctx, c, domain, target))
}
func (a *API) RemoveWorkDNS(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	defer cancel()
	return busError(a.service.RemoveWorkDNS(ctx, c, id))
}
