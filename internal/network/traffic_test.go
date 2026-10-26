package network

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadTUNCountersPreservesDirectionAndReportsUnavailable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "statistics"), 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, path), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("ifindex", "12\n")
	write("statistics/rx_bytes", "123456\n")
	write("statistics/tx_bytes", "2345\n")
	at := time.Now()
	got := readTUNCounters(dir, at)
	if !got.Valid || got.IfIndex != 12 || got.RXBytes != 123456 || got.TXBytes != 2345 || !got.SampledAt.Equal(at) {
		t.Fatalf("wrong counters: %+v", got)
	}
	write("statistics/rx_bytes", "unavailable")
	if readTUNCounters(dir, at).Valid {
		t.Fatal("invalid RX accepted as zero")
	}
	write("statistics/rx_bytes", "123456\n")
	if err := os.Remove(filepath.Join(dir, "statistics/tx_bytes")); err != nil {
		t.Fatal(err)
	}
	if readTUNCounters(dir, at).Valid {
		t.Fatal("missing TX accepted as zero")
	}
}

func TestTrafficReaderDoesNotEnterNetworkWorkerOrTrustNameAlone(t *testing.T) {
	m := New(Config{StateDir: t.TempDir(), RuntimeDir: t.TempDir(), DryRun: true})
	m.mu.Lock()
	defer m.mu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- m.TrafficCounters().Valid }()
	select {
	case valid := <-done:
		if valid {
			t.Fatal("unowned TUN supplied counters")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("counter reader waited for network mutex")
	}
}
