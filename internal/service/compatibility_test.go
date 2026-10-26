package service

import (
	"context"
	"encoding/json"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"vault443/internal/model"
	"vault443/internal/store"
)

type compatibilityRuntime struct {
	fakeRuntime
	inspections atomic.Int32
	started     chan struct{}
	release     chan struct{}
}

func (r *compatibilityRuntime) VPNCompatibility(ctx context.Context) model.VPNCompatibility {
	r.inspections.Add(1)
	if r.started != nil {
		close(r.started)
		select {
		case <-r.release:
		case <-ctx.Done():
		}
	}
	return model.VPNCompatibility{Items: []model.VPNCompatibilityItem{{Interface: "tun0", Manager: "pritunl", Application: "Pritunl", Source: "automatic", Active: true, Verified: true, FullIPv4: true}}}
}

func TestCompatibilityReadOnlyAndForeignSessionPrivacy(t *testing.T) {
	s, _, st := setup(t)
	r := &compatibilityRuntime{}
	s.runtime = r
	c := Caller{UID: 1000}
	before := st.Snapshot()
	report := s.GetVPNCompatibility(context.Background(), c)
	if report.BusyByOtherUser || len(report.Items) != 1 || r.inspections.Load() != 1 || !reflect.DeepEqual(st.Snapshot(), before) || len(r.calls) != 0 {
		t.Fatal("read-only inspection failed or mutated session", report)
	}
	if err := st.Update(func(state *store.State) error {
		state.Desired = &store.Session{UID: 1001, ProfileID: "private"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report = s.GetVPNCompatibility(context.Background(), c)
	data, _ := json.Marshal(report)
	if !report.BusyByOtherUser || len(report.Items) != 0 || r.inspections.Load() != 1 || string(data) != `{"busyByOtherUser":true,"items":[],"message":"Используется другим пользователем"}` {
		t.Fatal("foreign session disclosed network discovery", string(data))
	}
}

func TestCompatibilityConcurrentTakeoverDoesNotLeakOrBlockControl(t *testing.T) {
	s, _, st := setup(t)
	r := &compatibilityRuntime{started: make(chan struct{}), release: make(chan struct{})}
	s.runtime = r
	done := make(chan model.VPNCompatibility, 1)
	go func() { done <- s.GetVPNCompatibility(context.Background(), Caller{UID: 1000}) }()
	<-r.started
	controlled := make(chan struct{})
	go func() {
		_ = s.Disconnect(context.Background(), Caller{UID: 1000})
		close(controlled)
	}()
	select {
	case <-controlled:
	case <-time.After(time.Second):
		close(r.release)
		t.Fatal("inspection blocked connection control")
	}
	if err := st.Update(func(state *store.State) error {
		state.Desired = &store.Session{UID: 1001, ProfileID: "private"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	close(r.release)
	if report := <-done; !report.BusyByOtherUser || len(report.Items) != 0 {
		t.Fatal("concurrent ownership change leaked discovery", report)
	}
}
