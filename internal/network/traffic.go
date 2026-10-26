package network

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vault443/internal/model"
)

type trafficHandler struct{ fn func(model.TUNCounters) }

// TrafficCounters is independent of the network worker mutex. Only the core
// launched by this Manager can make a device eligible; an unrelated interface
// with the same name is never used for accounting.
func (m *Manager) TrafficCounters() model.TUNCounters {
	if !m.trafficActive.Load() || !m.core.Alive() {
		return model.TUNCounters{}
	}
	epoch := m.trafficEpoch.Load()
	sample := readTUNCounters(filepath.Join("/sys/class/net", TunName), time.Now())
	if sample.IfIndex != m.trafficIfIndex.Load() || epoch != m.trafficEpoch.Load() || !m.trafficActive.Load() || !m.core.Alive() {
		return model.TUNCounters{}
	}
	sample.Epoch = epoch
	return sample
}

func readTUNCounters(dir string, now time.Time) model.TUNCounters {
	read := func(name string) (uint64, error) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	index, e1 := read("ifindex")
	rx, e2 := read("statistics/rx_bytes")
	tx, e3 := read("statistics/tx_bytes")
	after, e4 := read("ifindex")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || index == 0 || index != after {
		return model.TUNCounters{}
	}
	return model.TUNCounters{IfIndex: index, RXBytes: rx, TXBytes: tx, SampledAt: now, Valid: true}
}

// The service installs a generation-bound observer. It performs only a short
// in-memory update, never calls network mutations, and ignores cancelled work.
func (m *Manager) SetTrafficHandler(fn func(model.TUNCounters)) {
	m.trafficHandler.Store(&trafficHandler{fn: fn})
}

func (m *Manager) observeTraffic() {
	if observer := m.trafficHandler.Load(); observer != nil && observer.fn != nil {
		observer.fn(m.TrafficCounters())
	}
}

func (m *Manager) stopCore(ctx context.Context) error {
	// Read while the owned TUN still exists, before Xray closes its descriptor.
	m.observeTraffic()
	m.trafficActive.Store(false)
	return m.core.StopContext(ctx)
}
