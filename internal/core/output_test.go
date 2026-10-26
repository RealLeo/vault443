package core

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vault443/internal/journal"
)

func TestOutputDrainBoundedAndSessionImmutable(t *testing.T) {
	j, e := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	old := j.NewSession(1000, "old", "private-key")
	next := j.NewSession(1001, "new")
	writer := newOutputWriter(old)
	if _, e = writer.Write([]byte("[Warning] partial private-")); e != nil {
		t.Fatal(e)
	}
	// New ownership must not reattribute an old process's trailing output.
	_ = newOutputWriter(next)
	writer.Write([]byte("key\n"))
	writer.Write(bytes.Repeat([]byte("x"), 2<<20))
	if len(writer.partial) > journal.MaxMessageBytes*4 {
		t.Fatal("unbounded output buffer")
	}
	writer.Write([]byte("\n[Error] next message\n[Debug] unterminated"))
	writer.Flush()
	j.Flush()
	p, e := j.Read(1000, "old", "", 500)
	if e != nil || len(p.Entries) != 4 {
		t.Fatalf("output %+v %v", p, e)
	}
	if p.Entries[0].Level != "warning" || p.Entries[2].Level != "error" || p.Entries[3].Level != "debug" {
		t.Fatal("output levels lost")
	}
	for _, r := range p.Entries {
		if r.SessionID != old.ID() || strings.Contains(r.Message, "private-key") {
			t.Fatal("session/redaction failed")
		}
	}
	if q, _ := j.Read(1001, "new", "", 500); len(q.Entries) != 0 {
		t.Fatal("late process output leaked to new owner")
	}
}
func TestRealProcessStdoutStderrDrained(t *testing.T) {
	j, e := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	w := newOutputWriter(j.NewSession(1000, "pipes"))
	c := exec.Command("/bin/sh", "-c", `printf '[Warning] stdout\n'; printf '[Error] stderr\n' >&2`)
	c.Stdout = w
	c.Stderr = w
	if e = c.Run(); e != nil {
		t.Fatal(e)
	}
	w.Flush()
	j.Flush()
	p, e := j.Read(1000, "pipes", "", 20)
	if e != nil || len(p.Entries) != 2 {
		t.Fatalf("pipes not captured %+v %v", p, e)
	}
}
func TestWarningAndDebugConfigsKeepAccessDisabled(t *testing.T) {
	for _, debug := range []bool{false, true} {
		p := testProfile()
		p.DebugLogging = debug
		b, e := Build(p, testOptions())
		if e != nil {
			t.Fatal(e)
		}
		var cfg struct {
			Log struct {
				Level  string `json:"loglevel"`
				Access string `json:"access"`
				Error  string `json:"error"`
				DNS    bool   `json:"dnsLog"`
			}
		}
		if e = json.Unmarshal(b, &cfg); e != nil {
			t.Fatal(e)
		}
		want := "warning"
		if debug {
			want = "debug"
		}
		if cfg.Log.Level != want || cfg.Log.Access != "none" || cfg.Log.Error != "" || cfg.Log.DNS {
			t.Fatalf("unsafe logging config %+v", cfg.Log)
		}
		if binary := os.Getenv("XRAY_TEST_BINARY"); binary != "" {
			path := filepath.Join(t.TempDir(), "core.json")
			if e = os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			output, e := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput()
			if e != nil {
				t.Fatalf("pinned core rejected debug=%v config: %s", debug, output)
			}
		}
	}
}
