package main

// Private stdin wire contract with internal/model.OutlineRuntime. Kept in this
// standalone module so the adapter does not inherit the supervisor toolchain
// or dependency graph. End-to-end tests exercise the serialized contract.
type outlineRuntime struct {
	Transport *outlineTransport `json:"transport"`
	Resolved  map[string]string `json:"resolved"`
	Interface string            `json:"interface"`
	Mark      uint32            `json:"mark"`
	Username  string            `json:"username"`
	Password  string            `json:"password"`
}
type outlineTransport struct {
	TCP *outlineNode `json:"tcp,omitempty"`
	UDP *outlineNode `json:"udp,omitempty"`
}
type outlineNode struct {
	Type     string       `json:"type"`
	Address  string       `json:"address,omitempty"`
	URL      string       `json:"url,omitempty"`
	Cipher   string       `json:"cipher,omitempty"`
	Secret   string       `json:"secret,omitempty"`
	Prefix   []byte       `json:"prefix,omitempty"`
	Endpoint *outlineNode `json:"endpoint,omitempty"`
	Dialer   *outlineNode `json:"dialer,omitempty"`
}
