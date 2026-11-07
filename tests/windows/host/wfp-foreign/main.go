//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Isolated QA fixture only. No VPN journal, Manager, IPC, service, firewall
// policy, or network configuration is read or modified by this tool.
// Existing WFP containers are read, never created, changed, or deleted.
// It adds/deletes exactly one independently journalled persistent BLOCK filter.
const markerContent = "Vault443 isolated Windows fixture"
const description = "Isolated QA foreign-reference uninstall-abort fixture"

type fixtureJournal struct {
	Version       int    `json:"version"`
	Machine       string `json:"machine"`
	ControllerSID string `json:"controllerSID"`
	RuleID        string `json:"ruleId"`
	Token         string `json:"token"`
	Name          string `json:"name"`
}

func stableID(label string) windows.GUID {
	h := sha256.Sum256([]byte("Vault443.Windows.WFP.1:" + label))
	return windows.GUID{Data1: uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]), Data2: uint16(h[4])<<8 | uint16(h[5]), Data3: uint16(h[6])<<8 | uint16(h[7]), Data4: [8]byte(h[8:16])}
}

var providerID = wf.ProviderID(stableID("provider"))
var sublayerID = wf.SublayerID(stableID("sublayer"))

func protected(path string, directory bool) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attr, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (attr&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("QA path is a reparse point or has the wrong kind")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || (owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return errors.New("QA path is not owned by SYSTEM or Administrators")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("QA path has no private DACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid != "S-1-5-18" && sid != "S-1-5-32-544" && ace.Mask != 0 {
			return errors.New("QA path grants access outside SYSTEM/Administrators")
		}
	}
	return nil
}

func qaIdentity() (string, string, string, error) {
	machine, err := os.Hostname()
	if err != nil || (!strings.EqualFold(machine, "VAULT443-WIN10") && !strings.EqualFold(machine, "VAULT443-WIN11")) {
		return "", "", "", errors.New("named isolated QA VM required")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SystemInformation`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", "", err
	}
	model, _, err := key.GetStringValue("SystemProductName")
	key.Close()
	if err != nil || !strings.Contains(strings.ToLower(model), "virtualbox") {
		return "", "", "", errors.New("VirtualBox QA guest required")
	}
	token := windows.GetCurrentProcessToken()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", "", "", err
	}
	member, err := windows.Token(0).IsMember(admin)
	if err != nil || !member || !token.IsElevated() {
		return "", "", "", errors.New("explicit UAC administrator execution required")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return "", "", "", err
	}
	sid := user.User.Sid.String()
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", "", "", err
	}
	root := filepath.Join(programData, "Vault443-QA")
	if err := protected(root, true); err != nil {
		return "", "", "", err
	}
	for _, name := range []string{"marker", "qa-inputs.json"} {
		if err := protected(filepath.Join(root, name), false); err != nil {
			return "", "", "", err
		}
	}
	marker, err := os.ReadFile(filepath.Join(root, "marker"))
	if err != nil || strings.TrimSpace(string(marker)) != markerContent {
		return "", "", "", errors.New("protected QA marker mismatch")
	}
	data, err := os.ReadFile(filepath.Join(root, "qa-inputs.json"))
	if err != nil || len(data) > 1<<20 {
		return "", "", "", errors.New("invalid protected QA configuration")
	}
	var config struct {
		Machine       string `json:"machine"`
		ControllerSID string `json:"controllerSID"`
	}
	if json.Unmarshal(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}), &config) != nil || !strings.EqualFold(config.Machine, machine) || config.ControllerSID != sid {
		return "", "", "", errors.New("current UAC account is not the protected QA controller")
	}
	return root, machine, sid, nil
}

func privateFile(path string, creation uint32) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, creation, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	if err = protected(path, false); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func writeJournal(path string, j fixtureJournal) error {
	temporary := path + "." + j.Token + ".tmp"
	f, err := privateFile(temporary, windows.CREATE_NEW)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err = json.NewEncoder(f).Encode(j); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	a, _ := windows.UTF16PtrFromString(temporary)
	b, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(a, b, windows.MOVEFILE_WRITE_THROUGH)
}

func validateJournal(j fixtureJournal, machine, sid string) (wf.RuleID, error) {
	guid, err := windows.GUIDFromString(j.RuleID)
	token, tokenErr := hex.DecodeString(j.Token)
	if err != nil || guid == (windows.GUID{}) || j.Version != 1 || !strings.EqualFold(j.Machine, machine) || j.ControllerSID != sid || tokenErr != nil || len(token) != 16 || strings.ToLower(j.Token) != j.Token || j.Name != "Vault443 QA foreign-reference "+j.Token {
		return wf.RuleID{}, errors.New("private foreign-reference journal identity mismatch")
	}
	return wf.RuleID(guid), nil
}

func fixtureRule(j fixtureJournal, id wf.RuleID) *wf.Rule {
	return &wf.Rule{ID: id, Name: j.Name, Description: description, Provider: providerID, Sublayer: sublayerID, Layer: wf.LayerALEAuthConnectV4, Persistent: true, Action: wf.ActionBlock, Weight: 1, Conditions: []*wf.Match{
		{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: netip.MustParsePrefix("198.51.100.254/32")},
		{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(9)},
		{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoTCP},
	}}
}

func verifyRule(r *wf.Rule, j fixtureJournal, id wf.RuleID) error {
	want := fixtureRule(j, id)
	if r.ID != want.ID || r.Name != want.Name || r.Description != want.Description || r.Provider != providerID || r.Sublayer != sublayerID || r.Layer != want.Layer || r.Weight != 1 || r.Action != wf.ActionBlock || !r.Persistent || r.BootTime || r.HardAction || r.PermitIfMissing || r.Callout != (wf.CalloutID{}) || len(r.ProviderData) != 0 || len(r.Conditions) != 3 {
		return errors.New("foreign-reference filter changed; refusing deletion")
	}
	seen := map[wf.FieldID]bool{}
	for _, condition := range r.Conditions {
		if condition == nil || condition.Op != wf.MatchTypeEqual || seen[condition.Field] {
			return errors.New("foreign-reference condition changed; refusing deletion")
		}
		seen[condition.Field] = true
		valid := false
		switch condition.Field {
		case wf.FieldIPRemoteAddress:
			switch value := condition.Value.(type) {
			case netip.Prefix:
				valid = value == netip.MustParsePrefix("198.51.100.254/32")
			case netip.Addr:
				valid = value == netip.MustParseAddr("198.51.100.254")
			}
		case wf.FieldIPRemotePort:
			value, ok := condition.Value.(uint16)
			valid = ok && value == 9
		case wf.FieldIPProtocol:
			switch value := condition.Value.(type) {
			case uint8:
				valid = value == uint8(wf.IPProtoTCP)
			case wf.IPProto:
				valid = value == wf.IPProtoTCP
			}
		}
		if !valid {
			return errors.New("foreign-reference condition changed; refusing deletion")
		}
	}
	return nil
}

func findRule(s *wf.Session, id wf.RuleID) (*wf.Rule, error) {
	rules, err := s.Rules()
	if err != nil {
		return nil, errors.New("cannot inspect native WFP filters")
	}
	for _, r := range rules {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, nil
}

func deleteVerifiedRule(s *wf.Session, j fixtureJournal, id wf.RuleID) error {
	field := reflect.ValueOf(s).Elem().FieldByName("handle")
	if !field.IsValid() || field.Kind() != reflect.Uintptr {
		return errors.New("unsupported pinned WFP session layout")
	}
	handle := uintptr(field.Uint())
	dll := windows.NewLazySystemDLL("fwpuclnt.dll")
	begin, commit, abort := dll.NewProc("FwpmTransactionBegin0"), dll.NewProc("FwpmTransactionCommit0"), dll.NewProc("FwpmTransactionAbort0")
	code, _, _ := begin.Call(handle, 0)
	if code != 0 {
		return windows.Errno(code)
	}
	defer abort.Call(handle)
	r, err := findRule(s, id)
	if err != nil {
		return err
	}
	if r != nil {
		if err = verifyRule(r, j, id); err != nil {
			return err
		}
		if err = s.DeleteRule(id); err != nil {
			return fmt.Errorf("fixture DeleteRule failed; journal retained: %w", err)
		}
		if r, err = findRule(s, id); err != nil || r != nil {
			return errors.New("fixture deletion not confirmed; journal retained")
		}
	}
	code, _, _ = commit.Call(handle)
	if code != 0 {
		return windows.Errno(code)
	}
	return nil
}

func run(mode string) error {
	root, machine, sid, err := qaIdentity()
	if err != nil {
		return err
	}
	lock, err := privateFile(filepath.Join(root, "foreign-reference.lock"), windows.OPEN_ALWAYS)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		return errors.New("another foreign-reference helper is running")
	}
	path := filepath.Join(root, "foreign-reference.json")
	s, err := wf.New(&wf.Options{Name: "Vault443 isolated QA foreign reference", Dynamic: false, TransactionStartTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer s.Close()
	providers, err := s.Providers()
	if err != nil {
		return err
	}
	found := false
	for _, p := range providers {
		if p.ID == providerID {
			if p.Disabled {
				return errors.New("QA provider disabled; refusing ambiguous fixture enumeration")
			}
			found = true
		}
	}
	if !found {
		return errors.New("installed Vault443 provider must already exist")
	}
	sublayers, err := s.Sublayers()
	if err != nil {
		return err
	}
	found = false
	for _, sl := range sublayers {
		if sl.ID == sublayerID {
			if sl.Provider != providerID {
				return errors.New("QA sublayer belongs to another provider")
			}
			found = true
		}
	}
	if !found {
		return errors.New("installed Vault443 sublayer must already exist")
	}
	var j fixtureJournal
	var id wf.RuleID
	if mode == "setup" {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("fixture journal already exists or cannot be inspected; cleanup first")
		}
		random := make([]byte, 16)
		if _, err = rand.Read(random); err != nil {
			return err
		}
		guid, e := windows.GenerateGUID()
		if e != nil {
			return e
		}
		j = fixtureJournal{Version: 1, Machine: machine, ControllerSID: sid, RuleID: guid.String(), Token: hex.EncodeToString(random)}
		j.Name = "Vault443 QA foreign-reference " + j.Token
		id = wf.RuleID(guid)
		if err = writeJournal(path, j); err != nil {
			return err
		}
		if err = s.AddRule(fixtureRule(j, id)); err != nil {
			return fmt.Errorf("fixture AddRule failed; journal retained: %w", err)
		}
		r, err := findRule(s, id)
		if err != nil {
			return err
		}
		if r == nil {
			return errors.New("new fixture filter was not visible; journal retained")
		}
		if err = verifyRule(r, j, id); err != nil {
			return err
		}
	} else {
		if err = protected(path, false); err != nil {
			return err
		}
		data, e := os.ReadFile(path)
		if e != nil || len(data) > 8192 {
			return errors.New("invalid private fixture journal")
		}
		if json.Unmarshal(data, &j) != nil {
			return errors.New("invalid private fixture journal JSON")
		}
		id, err = validateJournal(j, machine, sid)
		if err != nil {
			return err
		}
		if err = deleteVerifiedRule(s, j, id); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Mode   string `json:"mode"`
		RuleID string `json:"ruleId"`
		Result string `json:"result"`
	}{mode, j.RuleID, "complete"})
}

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "setup" && os.Args[1] != "cleanup") {
		fmt.Fprintln(os.Stderr, "usage: vault443-wfp-foreign.exe setup|cleanup (explicit UAC, isolated QA controller only)")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
