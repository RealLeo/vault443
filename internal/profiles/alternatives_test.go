package profiles

import (
	"strings"
	"testing"
)

func TestFirstSupportedSelectsUsableSimpleSS2022(t *testing.T) {
	first := `{$type: shadowsocks, endpoint: "entry.example:443", cipher: 2022-blake3-aes-128-gcm, secret: "AAAAAAAAAAAAAAAAAAAAAA=="}`
	fallback := `{$type: shadowsocks, endpoint: "fallback.example:443", cipher: aes-256-gcm, secret: "fallback-secret"}`
	document := `transport:
  $type: tcpudp
  tcp: NODE
  udp: NODE
`
	direct, err := ParseOutline(strings.ReplaceAll(document, "NODE", first), "https://source.example/key", "Direct")
	if err != nil {
		t.Fatal(err)
	}
	alt, err := ParseOutline(strings.ReplaceAll(document, "NODE", `{$type: first-supported, options: [`+first+`, `+fallback+`]}`), "https://source.example/key", "Alternatives")
	if err != nil {
		t.Fatal(err)
	}
	if direct.Method != "2022-blake3-aes-128-gcm" || direct.Outline != nil {
		t.Fatalf("control not direct Xray SS2022: %+v", direct)
	}
	if alt.Method != "2022-blake3-aes-128-gcm" || alt.Server != "entry.example" {
		t.Fatalf("unexpected alternative result %+v", alt)
	}
	_, err = ParseOutline(strings.ReplaceAll(document, "NODE", `{$type: first-supported, options: [`+first+`]}`), "https://source.example/key", "Only2022")
	if err != nil {
		t.Fatal("sole supported option rejected", err)
	}
}

func TestAlternativesUseWholeConfigurationAndPreserveOrder(t *testing.T) {
	ss2022 := `{$type: shadowsocks, endpoint: 'entry.example:443', cipher: 2022-blake3-aes-128-gcm, secret: 'AAAAAAAAAAAAAAAAAAAAAA=='}`
	aead := `{$type: shadowsocks, endpoint: 'fallback.example:443', cipher: aes-256-gcm, secret: 'synthetic'}`
	doc := `transport:
  $type: tcpudp
  tcp: {$type: first-supported, options: [SS2022, AEAD]}
  udp: {$type: first-supported, options: [AEAD, {$type: first-supported, options: [SS2022]}]}
`
	p, e := ParseOutline(strings.ReplaceAll(strings.ReplaceAll(doc, "SS2022", ss2022), "AEAD", aead), "https://source.example/key", "Test")
	if e != nil || p.Outline != nil || p.Method != "2022-blake3-aes-128-gcm" {
		t.Fatalf("TCP priority/full configuration lost: %+v %v", p, e)
	}
	// An extended endpoint makes SS2022 unsupported by the final SDK backend.
	extended := `{$type: shadowsocks, endpoint: 'entry.example:443', cipher: 2022-blake3-aes-128-gcm, secret: 'AAAAAAAAAAAAAAAAAAAAAA==', prefix: 'POST '}`
	p, e = ParseOutline(strings.ReplaceAll(strings.ReplaceAll(doc, "SS2022", extended), "AEAD", aead), "https://source.example/key", "Test")
	if e != nil || p.Method != "aes-256-gcm" || p.Server != "fallback.example" {
		t.Fatalf("unsupported SDK combination selected: %+v %v", p, e)
	}
}

func TestAlternativesBoundCompleteCombinations(t *testing.T) {
	first := `{$type: shadowsocks, endpoint: 'entry.example:443', cipher: 2022-blake3-aes-128-gcm, secret: 'AAAAAAAAAAAAAAAAAAAAAA=='}`
	fallback := `{$type: shadowsocks, endpoint: 'other.example:443', cipher: aes-256-gcm, secret: 'synthetic'}`
	eight := func(node string) string {
		return `{$type: first-supported, options: [` + strings.TrimSuffix(strings.Repeat(node+",", 8), ",") + `]}`
	}
	doc := `transport: {$type: tcpudp, tcp: ` + eight(eight(first)) + `, udp: ` + eight(fallback) + `}`
	_, err := ParseOutline(doc, "https://source.example/key", "Test")
	if err == nil || !strings.Contains(err.Error(), "256 configurations") {
		t.Fatalf("search not bounded by complete combinations: %v", err)
	}
	// The same large search space is legal when its very first combination works.
	doc = `transport: {$type: tcpudp, tcp: ` + eight(eight(first)) + `, udp: ` + eight(first) + `}`
	if _, err = ParseOutline(doc, "https://source.example/key", "Test"); err != nil {
		t.Fatal(err)
	}
}
