// The HTTPS server uses Go's real HTTP/2 implementation because Xray's DoH
// client requires h2. All credentials and addresses belong to a private netns.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func answer(q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("short DNS query")
	}
	end := 12
	var labels []string
	for end < len(q) && q[end] != 0 {
		if q[end]&0xc0 != 0 {
			return nil, errors.New("compressed question unsupported")
		}
		next := end + int(q[end]) + 1
		if next > len(q) {
			return nil, errors.New("invalid DNS label")
		}
		labels = append(labels, string(q[end+1:next]))
		end = next
	}
	end++
	if end+4 > len(q) {
		return nil, errors.New("invalid DNS question")
	}
	a := make([]byte, 12)
	copy(a, q[:2])
	binary.BigEndian.PutUint16(a[2:], 0x8180)
	binary.BigEndian.PutUint16(a[4:], 1)
	typ, class := binary.BigEndian.Uint16(q[end:]), binary.BigEndian.Uint16(q[end+2:])
	a = append(a, q[12:end+4]...)
	name := strings.ToLower(strings.Join(labels, "."))
	if typ == 1 && class == 1 && name != "web6.e2e.example.com" {
		binary.BigEndian.PutUint16(a[6:], 1)
		a = append(a, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 93, 184, 215, 14)
	} else if typ == 28 && class == 1 && (name == "web6.e2e.example.com" || name == "webdual.e2e.example.com" || name == "cp.cloudflare.com" || name == "www.gstatic.com") {
		binary.BigEndian.PutUint16(a[6:], 1)
		a = append(a, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16)
		a = append(a, net.ParseIP("2001:db8:66::14").To16()...)
	}
	return a, nil
}
func main() {
	web := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upload" {
			n, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 8<<20))
			if err != nil {
				http.Error(w, "upload rejected", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"received": n})
			return
		}
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		peer, _, _ := net.SplitHostPort(r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		payload := ""
		if r.URL.Path == "/large" {
			payload = strings.Repeat("vless-browser-payload-", 32768)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"marker": "vless-e2e-ok", "peer": peer, "payload": payload})
	})
	for _, address := range []string{"93.184.215.14:443", "[2001:db8:66::14]:443"} {
		go func(address string) {
			server := &http.Server{Addr: address, Handler: web, MaxHeaderBytes: 8192}
			log.Fatal(server.ListenAndServeTLS("/fixture/server.crt", "/fixture/server.key"))
		}(address)
	}
	go func() {
		log.Fatal(http.ListenAndServe("93.184.215.14:8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, _, _ := net.SplitHostPort(r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"marker": "vless-e2e-ok", "peer": peer})
		})))
	}()
	doh := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "application/dns-json" {
			name := r.URL.Query().Get("name")
			if strings.HasPrefix(name, "slow-") {
				log.Print("bootstrap DoH waiting for cancellation")
				select {
				case <-r.Context().Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
			response := map[string]any{"Status": 0, "Question": []any{map[string]any{"name": name, "type": 1}}}
			if strings.HasPrefix(name, "missing-") {
				response["Status"] = 3
			} else {
				response["Answer"] = []any{map[string]any{"name": name, "type": 1, "data": "203.0.113.1"}}
			}
			w.Header().Set("Content-Type", "application/dns-json")
			_ = json.NewEncoder(w).Encode(response)
			log.Printf("bootstrap DoH %s from %s", name, r.RemoteAddr)
			return
		}
		var q []byte
		var err error
		if r.Method == http.MethodPost {
			q, err = io.ReadAll(io.LimitReader(r.Body, 4097))
		} else {
			q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		}
		if err != nil || len(q) > 4096 {
			http.Error(w, "invalid query", 400)
			return
		}
		body, err := answer(q)
		if err != nil {
			http.Error(w, "invalid DNS query", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
		log.Printf("DoH %s from %s", r.Proto, r.RemoteAddr)
	})
	server := &http.Server{Addr: "1.1.1.1:443", Handler: doh, MaxHeaderBytes: 8192}
	log.Print("fixture ready")
	log.Fatal(server.ListenAndServeTLS("/fixture/server.crt", "/fixture/server.key"))
}
