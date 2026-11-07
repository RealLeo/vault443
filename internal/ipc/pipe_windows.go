package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/windows"
	"vault443/internal/securefs"
	"vault443/internal/service"
)

const PipeName = `\\.\pipe\Vault443.Service1`
const maxPipeFrame = 4 << 20
const maxPipePeers = 64
const firstPipeFrameTimeout = 8 * time.Second
const idlePipeFrameTimeout = 2 * time.Minute

// Generic write also grants FILE_CREATE_PIPE_INSTANCE. Clients must receive
// data access without the right to impersonate another server instance.
const pipeClientAccess = uint32(0x0012019b)

type pipeRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}
type pipeError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type pipeResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *pipeError      `json:"error,omitempty"`
}
type windowsUsers struct {
	Next      uint32            `json:"next"`
	Users     map[string]uint32 `json:"users"`
	Operators map[string]bool   `json:"operators"`
}
type pipePeer struct {
	conn net.Conn
	out  chan []byte
}
type pipeServer struct {
	mu      sync.Mutex
	users   windowsUsers
	path    string
	peers   map[*pipePeer]bool
	service *service.Service
	ctx     context.Context
}
type pipeIdentity struct{ caller service.Caller }

func (p pipeIdentity) UID(dbus.Sender) (uint32, error) { return p.caller.UID, nil }
func (p pipeIdentity) Groups(uint32) ([]string, error) {
	groups := []string{"vault443"}
	if p.caller.Admin {
		groups = append(groups, "admin")
	}
	return groups, nil
}
func (p pipeIdentity) LocalActive(uint32) (bool, error) { return true, nil }

// ServePipe reuses the existing authorized service method adapters. D-Bus is
// never opened on Windows; its Go value types remain an internal adapter detail.
func ServePipe(ctx context.Context, s *service.Service, stateDir string) error {
	p := &pipeServer{ctx: ctx, service: s, path: filepath.Join(stateDir, "windows-users.json"), peers: map[*pipePeer]bool{}, users: windowsUsers{Next: 1, Users: map[string]uint32{}, Operators: map[string]bool{}}}
	data, err := os.ReadFile(p.path)
	if err == nil {
		if len(data) > 1<<20 || json.Unmarshal(data, &p.users) != nil || p.users.Next == 0 || p.users.Users == nil || p.users.Operators == nil {
			return errors.New("invalid private Windows identity registry")
		}
		seen := map[uint32]bool{}
		for sid, uid := range p.users.Users {
			if _, e := windows.StringToSid(sid); e != nil || uid == 0 || uid >= p.users.Next || seen[uid] {
				return errors.New("invalid private Windows identity allocation")
			}
			seen[uid] = true
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0012019b;;;IU)", InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for peer := range p.peers {
			peer.conn.Close()
			delete(p.peers, peer)
		}
	}()
	s.OnChange(p.changed)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.accept(conn)
		}
	}()
	return nil
}
func (p *pipeServer) save() error {
	data, err := json.Marshal(p.users)
	if err != nil {
		return err
	}
	return securefs.Write(p.path, data)
}

func pipeToken(conn net.Conn) (windows.Token, error) {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("pipe does not expose an authenticated handle")
	}
	// Impersonation uses the context of the message just read, not a PID supplied
	// by the caller. The OS thread stays pinned until identity has been captured.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	r, _, err := proc.Call(f.Fd())
	if r == 0 {
		return 0, err
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			panic("cannot revert pipe client impersonation")
		}
	}()
	var token windows.Token
	err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	return token, err
}
func tokenIdentity(token windows.Token, consoleAdministrative bool) (sid string, admin bool, err error) {
	u, err := token.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	var session, size uint32
	err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &size)
	if err != nil {
		return "", false, err
	}
	if session != windows.WTSGetActiveConsoleSessionId() {
		return "", false, errors.New("an active local console session is required")
	}
	var console windows.Token
	if err = windows.WTSQueryUserToken(session, &console); err != nil {
		return "", false, err
	}
	defer console.Close()
	cu, err := console.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", false, err
	}
	admin, err = token.IsMember(adminSID)
	if err != nil {
		return "", false, err
	}
	// An over-the-shoulder UAC token belongs to the approving administrator,
	// but these narrow actions apply to the actual console user's profiles.
	// Derive that SID from WTS; neither helper nor frontend may select it.
	if consoleAdministrative && admin {
		return cu.User.Sid.String(), true, nil
	}
	if !windows.EqualSid(cu.User.Sid, u.User.Sid) {
		return "", false, errors.New("the local login session changed")
	}
	return u.User.Sid.String(), admin, nil
}
func (p *pipeServer) caller(conn net.Conn, method string, params []json.RawMessage) (service.Caller, bool, error) {
	token, err := pipeToken(conn)
	if err != nil {
		return service.Caller{}, false, err
	}
	defer token.Close()
	consoleAdministrative := method == "GrantConsoleOperator" || method == "SetBootProfile" || method == "SetVPNBinding"
	sid, admin, err := tokenIdentity(token, consoleAdministrative)
	if err != nil {
		return service.Caller{}, false, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if method == "GrantConsoleOperator" {
		if !admin || len(params) != 0 {
			return service.Caller{}, false, errors.New("administrator approval is required")
		}
		p.users.Operators[sid] = true
		return service.Caller{}, true, p.save()
	}
	if !p.users.Operators[sid] && !admin {
		return service.Caller{}, false, errors.New("this user has not been granted Vault 443 access")
	}
	uid := p.users.Users[sid]
	if uid == 0 {
		if p.users.Next == ^uint32(0) {
			return service.Caller{}, false, errors.New("Windows identity registry exhausted")
		}
		uid = p.users.Next
		p.users.Next++
		p.users.Users[sid] = uid
		if err = p.save(); err != nil {
			delete(p.users.Users, sid)
			p.users.Next--
			return service.Caller{}, false, err
		}
	}
	return service.Caller{UID: uid, Admin: admin}, false, nil
}
func (p *pipeServer) changed() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for peer := range p.peers {
		select {
		case peer.out <- []byte("{\"jsonrpc\":\"2.0\",\"method\":\"Changed\"}\n"):
		default:
			peer.conn.Close()
		}
	}
}

// Register before starting either per-client goroutine: unauthenticated and
// active clients share one bounded budget, including during cancellation.
func (p *pipeServer) accept(conn net.Conn) {
	p.mu.Lock()
	if p.ctx.Err() != nil || len(p.peers) >= maxPipePeers {
		p.mu.Unlock()
		conn.Close()
		return
	}
	if err := conn.SetReadDeadline(time.Now().Add(firstPipeFrameTimeout)); err != nil {
		p.mu.Unlock()
		conn.Close()
		return
	}
	peer := &pipePeer{conn: conn, out: make(chan []byte, 32)}
	p.peers[peer] = true
	p.mu.Unlock()
	go p.serve(peer)
}
func (p *pipeServer) serve(peer *pipePeer) {
	conn := peer.conn
	done := make(chan struct{})
	writerDone := make(chan struct{})
	defer close(done)
	defer func() { conn.Close(); p.mu.Lock(); delete(p.peers, peer); p.mu.Unlock() }()
	go func() {
		defer close(writerDone)
		defer conn.Close()
		for {
			select {
			case data := <-peer.out:
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(data); err != nil {
					conn.Close()
					return
				}
			case <-p.ctx.Done():
				return
			case <-done:
				return
			}
		}
	}()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), maxPipeFrame)
	first := true
	for {
		// Start the idle budget only when waiting for another complete frame,
		// not while a legitimate service operation is still being executed.
		if !first {
			if err := conn.SetReadDeadline(time.Now().Add(idlePipeFrameTimeout)); err != nil {
				return
			}
		}
		if !scanner.Scan() {
			return
		}
		first = false
		var request pipeRequest
		response := pipeResponse{JSONRPC: "2.0", ID: json.RawMessage("null")}
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&request)
		var extra any
		trailing := decoder.Decode(&extra)
		var id any
		idErr := json.Unmarshal(request.ID, &id)
		_, stringID := id.(string)
		_, numberID := id.(float64)
		if err != nil || trailing != io.EOF || idErr != nil || (!stringID && !numberID) || request.JSONRPC != "2.0" || len(request.ID) > 64 || len(request.Method) > 128 || len(request.Params) > 8 {
			response.Error = &pipeError{-32600, "Invalid request"}
		} else {
			response.ID = request.ID
			caller, handled, err := p.caller(conn, request.Method, request.Params)
			if err != nil {
				response.Error = &pipeError{-32001, "Access denied: " + err.Error()}
			} else if handled {
				response.Result = json.RawMessage("{}")
			} else {
				api := &API{ctx: p.ctx, service: p.service, auth: Authorizer{Source: pipeIdentity{caller}, OperatorGroup: "vault443"}}
				response.Result, response.Error = dispatchPipe(api, request)
			}
		}
		data, err := json.Marshal(response)
		if err != nil {
			return
		}
		data = append(data, '\n')
		select {
		case peer.out <- data:
		case <-writerDone:
			return
		case <-p.ctx.Done():
			return
		}
	}
}
func dispatchPipe(api *API, request pipeRequest) (json.RawMessage, *pipeError) {
	method := reflect.ValueOf(api).MethodByName(request.Method)
	if !method.IsValid() {
		return nil, &pipeError{-32601, "Unknown method"}
	}
	t := method.Type()
	if t.NumIn() != len(request.Params)+1 || t.In(0) != reflect.TypeOf(dbus.Sender("")) {
		return nil, &pipeError{-32602, "Invalid parameters"}
	}
	args := []reflect.Value{reflect.ValueOf(dbus.Sender(":windows-pipe"))}
	for i, data := range request.Params {
		kind := t.In(i + 1).Kind()
		if kind != reflect.String && kind != reflect.Bool && kind != reflect.Int32 {
			return nil, &pipeError{-32602, "Invalid parameters"}
		}
		value := reflect.New(t.In(i + 1))
		if json.Unmarshal(data, value.Interface()) != nil {
			return nil, &pipeError{-32602, "Invalid parameters"}
		}
		args = append(args, value.Elem())
	}
	result := method.Call(args)
	last := result[len(result)-1]
	if !last.IsNil() {
		e := last.Interface().(*dbus.Error)
		return nil, &pipeError{-32000, e.Error()}
	}
	if len(result) == 1 {
		return json.RawMessage("{}"), nil
	}
	data := []byte(result[0].String())
	if !json.Valid(data) {
		return nil, &pipeError{-32603, "Invalid service response"}
	}
	return json.RawMessage(data), nil
}

// PipeCall is shared by the narrow elevated helper and acceptance runner.
func verifySystemServer(conn net.Conn) error {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("pipe has no verifiable server handle")
	}
	// The pipe owner is readable without granting users access to the service
	// process token. An ordinary user cannot assign SYSTEM ownership.
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("the named pipe is not owned by LocalSystem")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("the service pipe has no restrictive DACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		trusted := sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
		if !trusted && ace.Mask&(windows.GENERIC_ALL|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_APPEND_DATA) != 0 {
			return errors.New("the pipe permits untrusted server instances")
		}
	}
	return nil
}
func PipeCall(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	conn, err := winio.DialPipeAccessImpLevel(ctx, PipeName, pipeClientAccess, winio.PipeImpLevelIdentification)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Authenticate before sending profile material or elevated operations.
	if err = verifySystemServer(conn); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err = json.NewEncoder(conn).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(io.LimitReader(conn, maxPipeFrame))
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var response pipeResponse
		if json.Unmarshal(line, &response) != nil {
			return nil, errors.New("invalid service response")
		}
		if len(response.ID) == 0 {
			continue
		}
		if response.Error != nil {
			return nil, fmt.Errorf("%s", response.Error.Message)
		}
		return response.Result, nil
	}
}
