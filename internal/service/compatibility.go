package service

import (
	"context"
	"time"

	"vault443/internal/model"
)

type vpnCompatibilityReader interface {
	VPNCompatibility(context.Context) model.VPNCompatibility
}

// GetVPNCompatibility deliberately avoids the service mutex during discovery:
// a read-only UI poll must not delay Disconnect, Connect, or ownership changes.
// The store provides its own atomic snapshots. Ownership is checked again after
// I/O so a concurrent takeover cannot expose another user's network information.
func (s *Service) GetVPNCompatibility(ctx context.Context, c Caller) model.VPNCompatibility {
	busy := func() bool { return s.busyFor(c) }
	private := model.VPNCompatibility{BusyByOtherUser: true, Items: []model.VPNCompatibilityItem{}, Message: "Используется другим пользователем"}
	if busy() {
		return private
	}
	out := model.VPNCompatibility{Items: []model.VPNCompatibilityItem{}, Message: "Проверка совместимости недоступна в этой службе."}
	if reader, ok := s.runtime.(vpnCompatibilityReader); ok {
		ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		out = reader.VPNCompatibility(ctx)
	}
	if busy() {
		return private
	}
	if out.Items == nil {
		out.Items = []model.VPNCompatibilityItem{}
	}
	return out
}
