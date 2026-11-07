package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivateControlRejectsAmbiguousFrames(t *testing.T) {
	for _, input := range []string{`{"uapi":"x","command":"run"}`, `{"uapi":"x"} {"uapi":"y"}`, `[]`, `{"probe":[42]}`} {
		var c command
		if decodeFrame([]byte(input), &c) == nil {
			t.Fatalf("accepted ambiguous private frame %s", input)
		}
	}
	var c command
	if err := decodeFrame([]byte(`{"uapi":"public_key=abc\nupdate_only=true\n","probe":["abc"],"bind4":7}`), &c); err != nil || c.Bind4 == nil || *c.Bind4 != 7 {
		t.Fatalf("valid private update rejected: %+v %v", c, err)
	}
}
func TestObservationNeverPublishesPrivateUAPIFields(t *testing.T) {
	secret := strings.Repeat("ac", 32)
	public := strings.Repeat("bd", 32)
	input := "private_key=" + secret + "\nlisten_port=51820\npublic_key=" + public + "\npreshared_key=" + secret + "\nlast_handshake_time_sec=1700000000\nrx_bytes=42\ntx_bytes=99\nendpoint=192.0.2.1:51820\n"
	observation, err := observation(input)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "preshared") || strings.Contains(string(data), "private_key") {
		t.Fatal("credential crossed observation boundary")
	}
	if len(observation.Peers) != 1 || observation.Peers[0].Key != public || observation.Peers[0].RX != 42 || observation.Peers[0].Handshake != 1700000000 {
		t.Fatalf("authentication observation lost: %+v", observation)
	}
}
func TestObservationBoundsAndMalformedCounters(t *testing.T) {
	if _, err := observation("public_key=abc\nlast_handshake_time_sec=not-a-time\n"); err == nil {
		t.Fatal("malformed timestamp accepted")
	}
	if _, err := observation(strings.Repeat("public_key=abc\n", 33)); err == nil {
		t.Fatal("unbounded peer observation accepted")
	}
}
