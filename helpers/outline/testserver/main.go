// Disposable test-only WebSocket gateway. It forwards opaque Shadowsocks bytes
// to the independent Xray fixture; it implements no cipher or proxy protocol.
package main

import (
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if os.Getenv("VAULT443_E2E_ISOLATED") != "1" {
		log.Fatal("isolated fixture required")
	}
	for _, endpoint := range []string{"1.1.1.1:9999", "1.1.1.1:443"} {
		go func() {
			c, e := net.ListenPacket("udp", endpoint)
			if e != nil {
				log.Fatal(e)
			}
			b := make([]byte, 65535)
			for {
				n, a, e := c.ReadFrom(b)
				if e != nil {
					return
				}
				_, _ = c.WriteTo(b[:n], a)
			}
		}()
	}
	upgrader := websocket.Upgrader{}
	http.HandleFunc("/tcp", func(w http.ResponseWriter, r *http.Request) {
		ws, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer ws.Close()
		upstream, e := net.DialTimeout("tcp", "192.0.2.1:8501", 3*time.Second)
		if e != nil {
			return
		}
		defer upstream.Close()
		go func() {
			defer ws.Close()
			b := make([]byte, 32768)
			for {
				n, e := upstream.Read(b)
				if e != nil {
					return
				}
				if ws.WriteMessage(websocket.BinaryMessage, b[:n]) != nil {
					return
				}
			}
		}()
		for {
			_, reader, e := ws.NextReader()
			if e != nil {
				return
			}
			if _, e = io.Copy(upstream, reader); e != nil {
				return
			}
		}
	})
	http.HandleFunc("/udp", func(w http.ResponseWriter, r *http.Request) {
		ws, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer ws.Close()
		upstream, e := net.DialTimeout("udp", "192.0.2.1:8502", 3*time.Second)
		if e != nil {
			return
		}
		defer upstream.Close()
		go func() {
			defer ws.Close()
			b := make([]byte, 65535)
			for {
				n, e := upstream.Read(b)
				if e != nil {
					return
				}
				if ws.WriteMessage(websocket.BinaryMessage, b[:n]) != nil {
					return
				}
			}
		}()
		for {
			_, b, e := ws.ReadMessage()
			if e != nil {
				return
			}
			if _, e = upstream.Write(b); e != nil {
				return
			}
		}
	})
	server := http.Server{Addr: "192.0.2.1:9443", ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServeTLS("/fixture/server.crt", "/fixture/server.key"))
}
