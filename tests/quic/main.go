// Test-only HTTP/3 endpoints. This binary is never shipped or run on the host.
package main

import (
	"fmt"
	"github.com/quic-go/quic-go/http3"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if os.Getenv("VAULT443_E2E_ISOLATED") != "1" {
		log.Fatal("isolated fixture required")
	}
	if _, e := os.Stat("/.dockerenv"); e != nil {
		log.Fatal(e)
	}
	payload := strings.Repeat("vault443-http3-", 8192)
	if len(os.Args) == 2 && os.Args[1] == "server" {
		s := http3.Server{Addr: "93.184.215.14:443", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.RemoteAddr, "192.0.2.2:") {
				http.Error(w, "direct path refused", 403)
				return
			}
			io.WriteString(w, payload)
		})}
		log.Fatal(s.ListenAndServeTLS("/fixture/server.crt", "/fixture/server.key"))
	}
	tr := &http3.Transport{}
	defer tr.Close()
	c := http.Client{Transport: tr, Timeout: 8 * time.Second}
	r, e := c.Get("https://93.184.215.14/")
	if e != nil {
		log.Fatal(e)
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil || r.ProtoMajor != 3 || string(b) != payload {
		log.Fatal("HTTP/3 body/protocol mismatch", e)
	}
	fmt.Println("PASS: certificate-verified HTTP/3 over UDP/443, complete 112 KiB response")
}
