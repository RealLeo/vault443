package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"vault443/internal/service"
)

const BusName = "org.vault443.Service1"
const ObjectPath = dbus.ObjectPath("/org/vault443/Service1")

type API struct {
	ctx     context.Context
	service *service.Service
	auth    Authorizer
}

func Serve(ctx context.Context, conn *dbus.Conn, s *service.Service) error {
	return serve(ctx, conn, s, Authorizer{Source: SystemIdentity{Conn: conn}, OperatorGroup: "vault443"})
}

func serve(ctx context.Context, conn *dbus.Conn, s *service.Service, auth Authorizer) error {
	api := &API{ctx: ctx, service: s, auth: auth}
	if err := conn.Export(api, ObjectPath, BusName); err != nil {
		return err
	}
	node := &introspect.Node{Name: string(ObjectPath), Interfaces: []introspect.Interface{introspect.IntrospectData, {Name: BusName, Methods: introspect.Methods(api), Signals: []introspect.Signal{{Name: "Changed"}}}}}
	if err := conn.Export(introspect.NewIntrospectable(node), ObjectPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	reply, err := conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New("another Vault 443 daemon owns the D-Bus name")
	}
	s.OnChange(func() { _ = conn.Emit(ObjectPath, BusName+".Changed") })
	return nil
}
func busError(err error) *dbus.Error {
	if err == nil {
		return nil
	}
	return dbus.NewError(BusName+".Error", []interface{}{err.Error()})
}
func forbidden(err error) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []interface{}{err.Error()})
}
func result(v interface{}, err error) (string, *dbus.Error) {
	if err != nil {
		return "", busError(err)
	}
	b, err := json.Marshal(v)
	return string(b), busError(err)
}
func (a *API) caller(sender dbus.Sender) (service.Caller, *dbus.Error) {
	c, err := a.auth.Authorize(sender)
	if err != nil {
		return c, forbidden(err)
	}
	return c, nil
}
func (a *API) GetSnapshot(sender dbus.Sender) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	return result(a.service.GetSnapshot(c), nil)
}
func (a *API) PreviewImport(sender dbus.Sender, text string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	return result(a.service.PreviewImport(c, text), nil)
}
func (a *API) ImportProfiles(sender dbus.Sender, text string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.ImportProfiles(c, text)
	return result(r, err)
}
func (a *API) PrepareImport(sender dbus.Sender, source, kind, name string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	r, err := a.service.PrepareImport(ctx, c, source, kind, name)
	return result(r, err)
}
func (a *API) CommitImport(sender dbus.Sender, draftID, iconsJSON string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.CommitImport(c, draftID, iconsJSON)
	return result(r, err)
}
func (a *API) CancelImport(sender dbus.Sender, draftID string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.CancelImport(c, draftID))
}
func (a *API) UpdateProfile(sender dbus.Sender, id, name, iconID string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.UpdateProfile(c, id, name, iconID))
}
func (a *API) SetProfileDebug(sender dbus.Sender, id string, enabled bool) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.SetProfileDebug(c, id, enabled))
}
func (a *API) GetProfileLogs(sender dbus.Sender, id, cursor string, limit int32) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.GetProfileLogs(c, id, cursor, int(limit))
	return result(r, err)
}
func (a *API) ClearProfileLogs(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.ClearProfileLogs(c, id))
}
func (a *API) RequestConnect(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	operationID, err := a.service.RequestConnect(a.ctx, c, id)
	return result(map[string]string{"operationId": operationID}, err)
}
func (a *API) RequestDisconnect(sender dbus.Sender) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	operationID, err := a.service.RequestDisconnect(a.ctx, c)
	return result(map[string]string{"operationId": operationID}, err)
}
func (a *API) GetProfileDiagnostics(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	value, err := a.service.GetProfileDiagnostics(a.ctx, c, id)
	return result(value, err)
}
func (a *API) Connect(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	return busError(a.service.Connect(ctx, c, id))
}
func (a *API) Disconnect(sender dbus.Sender) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	return busError(a.service.Disconnect(ctx, c))
}
func (a *API) TakeControl(sender dbus.Sender) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	return busError(a.service.TakeControl(ctx, c))
}
func (a *API) RemoveProfile(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.RemoveProfile(c, id))
}
func (a *API) RenameProfile(sender dbus.Sender, id, name string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.RenameProfile(c, id, name))
}
func (a *API) AddSubscription(sender dbus.Sender, url, name string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	r, err := a.service.AddSubscription(ctx, c, url, name)
	return result(r, err)
}
func (a *API) RefreshSubscriptions(sender dbus.Sender) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 11*time.Minute)
	defer cancel()
	return result(a.service.RefreshSubscriptions(ctx, c), nil)
}

func (a *API) RemoveSubscription(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.RemoveSubscription(c, id))
}
func (a *API) SetBootProfile(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.SetBootProfile(c, id))
}
func (a *API) GetDiagnostics(sender dbus.Sender) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	return result(a.service.GetDiagnostics(ctx, c), nil)
}
func (a *API) GetVPNCompatibility(sender dbus.Sender) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	return result(a.service.GetVPNCompatibility(ctx, c), nil)
}
func (a *API) SetVPNBinding(sender dbus.Sender, binding string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	return busError(a.service.SetVPNBinding(ctx, c, binding))
}
