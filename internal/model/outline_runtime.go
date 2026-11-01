package model

// OutlineRuntime is private daemon-to-child data sent over a pipe. The child
// receives pre-bound loopback TCP/UDP descriptors, never interface ownership.
type OutlineRuntime struct {
	Transport *OutlineTransport `json:"transport"`
	Resolved  map[string]string `json:"resolved"`
	Interface string            `json:"interface"`
	Mark      uint32            `json:"mark"`
	Username  string            `json:"username"`
	Password  string            `json:"password"`
}
