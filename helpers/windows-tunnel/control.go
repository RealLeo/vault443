package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

type config struct {
	Interface string `json:"interface"`
	Kind      string `json:"kind"`
	MTU       int    `json:"mtu"`
	GUID      string `json:"guid"`
	UAPI      string `json:"uapi"`
	Bind4     uint32 `json:"bind4"`
	Bind6     uint32 `json:"bind6"`
}
type command struct {
	UAPI  string   `json:"uapi,omitempty"`
	Probe []string `json:"probe,omitempty"`
	Bind4 *uint32  `json:"bind4,omitempty"`
	Bind6 *uint32  `json:"bind6,omitempty"`
}
type peer struct {
	Key       string `json:"key"`
	Handshake int64  `json:"handshake"`
	RX        uint64 `json:"rx"`
	TX        uint64 `json:"tx"`
	Endpoint  string `json:"endpoint"`
}
type status struct {
	Ready bool   `json:"ready"`
	Peers []peer `json:"peers"`
}

func decodeFrame(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid control frame")
	}
	return nil
}
func observation(data string) (status, error) {
	out := status{Ready: true, Peers: []peer{}}
	var current *peer
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 65536), 2<<20)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			if len(out.Peers) >= 32 {
				return out, errors.New("peer limit exceeded")
			}
			out.Peers = append(out.Peers, peer{Key: value})
			current = &out.Peers[len(out.Peers)-1]
			continue
		}
		if current == nil {
			continue
		}
		var err error
		switch key {
		case "last_handshake_time_sec":
			current.Handshake, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			current.RX, err = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			current.TX, err = strconv.ParseUint(value, 10, 64)
		case "endpoint":
			current.Endpoint = value
		}
		if err != nil {
			return out, errors.New("invalid private engine observation")
		}
	}
	return out, scanner.Err()
}
