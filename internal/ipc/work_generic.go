package ipc

import "github.com/godbus/dbus/v5"

func (a *API) PrepareWorkImport(sender dbus.Sender, filesJSON string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.PrepareWorkImport(c, filesJSON)
	return result(r, err)
}
func (a *API) CommitWorkImport(sender dbus.Sender, draftID, iconsJSON string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.CommitWorkImport(c, draftID, iconsJSON)
	return result(r, err)
}
func (a *API) CancelWorkImport(sender dbus.Sender, draftID string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.CancelWorkImport(c, draftID))
}
func (a *API) UpdateWorkProfile(sender dbus.Sender, id, name, iconID string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.UpdateWorkProfile(c, id, name, iconID))
}
func (a *API) RemoveWorkProfile(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.RemoveWorkProfile(c, id))
}
func (a *API) SetWorkDebug(sender dbus.Sender, id string, enabled bool) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.SetWorkDebug(c, id, enabled))
}
func (a *API) RequestWorkConnect(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	id, err := a.service.RequestWorkConnect(a.ctx, c, id)
	return result(map[string]string{"operationId": id}, err)
}
func (a *API) RequestWorkDisconnect(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	id, err := a.service.RequestWorkDisconnect(a.ctx, c, id)
	return result(map[string]string{"operationId": id}, err)
}
func (a *API) GetWorkDiagnostics(sender dbus.Sender, id string) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.GetWorkDiagnostics(c, id)
	return result(r, err)
}
func (a *API) GetWorkLogs(sender dbus.Sender, id, cursor string, limit int32) (string, *dbus.Error) {
	c, e := a.caller(sender)
	if e != nil {
		return "", e
	}
	r, err := a.service.GetWorkLogs(c, id, cursor, int(limit))
	return result(r, err)
}
func (a *API) ClearWorkLogs(sender dbus.Sender, id string) *dbus.Error {
	c, e := a.caller(sender)
	if e != nil {
		return e
	}
	return busError(a.service.ClearWorkLogs(c, id))
}
