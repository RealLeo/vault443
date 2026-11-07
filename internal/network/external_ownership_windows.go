package network

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/core"
	"vault443/internal/securefs"
	"vault443/internal/winplatform"
)

type externalService struct {
	unit, path string
	args       []string
	running    bool
	pid        uint32
	workers    map[uint32]string
}

func secureExternalPath(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return errors.New("VPN executable must be installed on a local protected volume")
	}
	path = filepath.Clean(path)
	for current := path; ; current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil {
			return errors.New("external VPN executable is unavailable")
		}
		if current == path && !info.Mode().IsRegular() {
			return errors.New("external VPN executable is not a regular file")
		}
		if e = securefs.Check(info, current, 0, false); e != nil {
			return errors.New("external VPN executable path is not protected")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}
func externalProcess(pid uint32) (string, error) {
	process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return "", e
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if e = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); e != nil {
		return "", e
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return "", errors.New("external VPN process is not LocalSystem")
	}
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	if e = windows.QueryFullProcessImageName(process, 0, &buffer[0], &length); e != nil {
		return "", e
	}
	path := windows.UTF16ToString(buffer[:length])
	if e = secureExternalPath(path); e != nil {
		return "", e
	}
	return path, nil
}
func externalWorker(manager, path string) bool {
	name := strings.ToLower(filepath.Base(path))
	switch manager {
	case "wireguard", "wg-quick":
		return name == "wireguard.exe" || name == "amneziawg.exe" || name == "amneziawg-go.exe"
	case "openvpn":
		return name == "openvpn.exe"
	case "pritunl":
		return name == "openvpn.exe" || name == "pritunl-client-service.exe" || name == "pritunl-service.exe"
	}
	return false
}
func inspectExternalService(ctx context.Context, unit, manager string) (externalService, error) {
	result := externalService{unit: unit, workers: map[uint32]string{}}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	if !validWindowsName(unit) {
		return result, errors.New("a Windows VPN service must be specified")
	}
	scm, e := mgr.Connect()
	if e != nil {
		return result, e
	}
	defer scm.Disconnect()
	name, e := windows.UTF16PtrFromString(unit)
	if e != nil {
		return result, e
	}
	handle, e := windows.OpenService(scm.Handle, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return result, e
	}
	service := &mgr.Service{Name: unit, Handle: handle}
	defer service.Close()
	cfg, e := service.Config()
	if e != nil {
		return result, e
	}
	if !strings.EqualFold(cfg.ServiceStartName, "LocalSystem") && !strings.EqualFold(cfg.ServiceStartName, `NT AUTHORITY\SYSTEM`) {
		return result, errors.New("external VPN service must run as LocalSystem")
	}
	text, e := windows.UTF16PtrFromString(cfg.BinaryPathName)
	if e != nil {
		return result, e
	}
	expanded := make([]uint16, 32768)
	n, e := windows.ExpandEnvironmentStrings(text, &expanded[0], uint32(len(expanded)))
	if e != nil || n == 0 || n > uint32(len(expanded)) {
		return result, errors.New("invalid Windows VPN service executable")
	}
	args, e := windows.DecomposeCommandLine(windows.UTF16ToString(expanded))
	if e != nil || len(args) == 0 {
		return result, errors.New("invalid Windows VPN service command")
	}
	result.path, result.args = args[0], args[1:]
	if e = secureExternalPath(result.path); e != nil {
		return result, e
	}
	state, e := service.Query()
	if e != nil {
		return result, e
	}
	if state.State != svc.Running || state.ProcessId == 0 {
		return result, nil
	}
	path, e := externalProcess(state.ProcessId)
	if e != nil || !strings.EqualFold(filepath.Clean(path), filepath.Clean(result.path)) {
		return result, errors.New("VPN service process identity could not be verified")
	}
	result.running, result.pid = true, state.ProcessId
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return result, e
	}
	defer windows.CloseHandle(snapshot)
	parents := map[uint32]uint32{}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if e = windows.Process32First(snapshot, &entry); e != nil {
		return result, e
	}
	for count := 0; count < 8192; count++ {
		parents[entry.ProcessID] = entry.ParentProcessID
		entry.Size = uint32(unsafe.Sizeof(entry))
		if e = windows.Process32Next(snapshot, &entry); e != nil {
			break
		}
	}
	for pid := range parents {
		ancestor := pid
		owned := false
		for depth := 0; depth < 16 && ancestor != 0; depth++ {
			if ancestor == result.pid {
				owned = true
				break
			}
			next := parents[ancestor]
			if next == ancestor {
				break
			}
			ancestor = next
		}
		if !owned {
			continue
		}
		if len(result.workers) >= 32 {
			return result, errors.New("external VPN process limit exceeded")
		}
		candidate, e := externalProcess(pid)
		if e == nil && externalWorker(manager, candidate) {
			result.workers[pid] = candidate
		}
	}
	return result, nil
}

type udpOwners map[uint32]map[uint16]map[uint32]bool

func udpOwnerPorts() (udpOwners, error) {
	result := udpOwners{}
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedUdpTable")
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		result[family] = map[uint16]map[uint32]bool{}
		size := uint32(0)
		code, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 1, 0)
		if code != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && code != 0 {
			return nil, windows.Errno(code)
		}
		if size > 8<<20 {
			return nil, errors.New("UDP owner table exceeds limits")
		}
		if size < 4 {
			continue
		}
		buffer := make([]byte, size)
		code, _, _ = proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), 1, 0)
		if code != 0 {
			return nil, windows.Errno(code)
		}
		count := binary.LittleEndian.Uint32(buffer)
		row, portOffset, pidOffset := 12, 4, 8
		if family == windows.AF_INET6 {
			row, portOffset, pidOffset = 28, 20, 24
		}
		if uint64(count)*uint64(row)+4 > uint64(len(buffer)) {
			return nil, errors.New("invalid UDP owner table")
		}
		for i := 0; i < int(count); i++ {
			offset := 4 + i*row
			port := binary.BigEndian.Uint16(buffer[offset+portOffset:])
			pid := binary.LittleEndian.Uint32(buffer[offset+pidOffset:])
			if result[family][port] == nil {
				result[family][port] = map[uint32]bool{}
			}
			result[family][port][pid] = true
		}
	}
	return result, nil
}
func automaticWireGuardName(service externalService) (string, bool) {
	const prefix = "WireGuardTunnel$"
	if !strings.HasPrefix(strings.ToLower(service.unit), strings.ToLower(prefix)) || !strings.EqualFold(filepath.Base(service.path), "wireguard.exe") {
		return "", false
	}
	name := service.unit[len(prefix):]
	if !validWindowsName(name) {
		return "", false
	}
	for i, arg := range service.args {
		if strings.EqualFold(arg, "/tunnelservice") && i+1 < len(service.args) {
			profilePath := service.args[i+1]
			if secureExternalPath(profilePath) != nil {
				return "", false
			}
			profile := filepath.Base(profilePath)
			profile = strings.TrimSuffix(strings.TrimSuffix(profile, ".dpapi"), ".conf")
			return name, strings.EqualFold(profile, name)
		}
	}
	return "", false
}

type boundedExternalOutput struct{ data []byte }

func (b *boundedExternalOutput) Write(data []byte) (int, error) {
	if len(b.data)+len(data) > 256<<10 {
		return 0, errors.New("external VPN metadata exceeds limits")
	}
	b.data = append(b.data, data...)
	return len(data), nil
}
func externalWGRead(parent context.Context, path, name, field string) ([]byte, error) {
	if name == "all" || name == "interfaces" {
		return nil, errors.New("ambiguous WireGuard adapter name")
	}
	if e := secureExternalPath(path); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	command := exec.Command(path, "show", name, field)
	var output boundedExternalOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	var process core.Process
	if e := process.StartInstalled(ctx, command); e != nil {
		return nil, e
	}
	defer process.StopContext(context.Background())
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for process.Alive() {
		select {
		case <-ctx.Done():
			return nil, errors.New("WireGuard ownership query timed out")
		case <-timer.C:
		}
	}
	if command.ProcessState == nil || !command.ProcessState.Success() {
		return nil, errors.New("cannot read the installed WireGuard driver's public status")
	}
	return output.data, nil
}

// No configuration blob/private key is queried. The installed wg.exe command is
// fixed to public status fields and protected by the same DACL checks as engines.
func readKernelWireGuard(ctx context.Context, service externalService, name string, luid winipcfg.LUID, ports udpOwners) ([]winplatform.Endpoint, []string, error) {
	if !service.running {
		return nil, nil, errors.New("WireGuard service is not running")
	}
	expected, ok := automaticWireGuardName(service)
	if !ok || !strings.EqualFold(expected, name) {
		return nil, nil, errors.New("WireGuard service does not own this adapter name")
	}
	actual, e := winplatform.InterfaceByName(name)
	if e != nil || actual != luid {
		return nil, nil, errors.New("WireGuard adapter identity changed")
	}
	tool := filepath.Join(filepath.Dir(service.path), "wg.exe")
	data, e := externalWGRead(ctx, tool, name, "listen-port")
	if e != nil {
		return nil, nil, e
	}
	listen, e := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 16)
	if e != nil || listen == 0 {
		return nil, nil, errors.New("invalid WireGuard kernel listen port")
	}
	data, e = externalWGRead(ctx, tool, name, "endpoints")
	if e != nil {
		return nil, nil, e
	}
	var endpoints []winplatform.Endpoint
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, nil, errors.New("invalid WireGuard endpoint status")
		}
		if fields[1] == "(none)" {
			continue
		}
		remote, e := netip.ParseAddrPort(fields[1])
		if e != nil || !externalIP(remote.Addr()) || remote.Port() == 0 {
			return nil, nil, errors.New("invalid WireGuard kernel endpoint")
		}
		family := uint32(windows.AF_INET)
		if remote.Addr().Is6() {
			family = windows.AF_INET6
		}
		if !ports[family][uint16(listen)][4] {
			return nil, nil, errors.New("WireGuard kernel socket ownership could not be verified")
		}
		uplink, e := winplatform.PhysicalUplink(remote.Addr().Is6())
		if e != nil {
			return nil, nil, e
		}
		endpoints = append(endpoints, winplatform.Endpoint{Address: remote.Addr(), Port: remote.Port(), UDP: true, Interface: uint64(uplink.LUID), SourcePort: uint16(listen), Kernel: true})
		if len(endpoints) > 64 {
			return nil, nil, errors.New("WireGuard endpoint limit exceeded")
		}
	}
	data, e = externalWGRead(ctx, tool, name, "allowed-ips")
	if e != nil {
		return nil, nil, e
	}
	var routes []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, nil, errors.New("invalid WireGuard allowed IP status")
		}
		for _, raw := range fields[1:] {
			raw = strings.TrimSuffix(raw, ",")
			if raw == "(none)" {
				continue
			}
			p, e := netip.ParsePrefix(raw)
			if e != nil || !validExternalPrefix(p) {
				return nil, nil, errors.New("invalid WireGuard protected route")
			}
			if p.Bits() > 1 {
				routes = append(routes, p.Masked().String())
			}
			if len(routes) > 256 {
				return nil, nil, errors.New("WireGuard route limit exceeded")
			}
		}
	}
	return endpoints, routes, nil
}
