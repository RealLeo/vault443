// Test-only external VPN owner. Never include this program in a product stage.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/core"
	"vault443/internal/securefs"
)

const (
	serviceName = "CorpExternalOpenVPNFixture"
	imagePath   = `C:\Program Files\Vault443ExternalFixture\vault443-external-openvpn.exe`
	dataDir     = `C:\ProgramData\Vault443ExternalFixture`
	enginePath  = `C:\Program Files\Vault443\openvpn\openvpn.exe`
	driverPath  = `C:\Program Files\Vault443\wintun.dll`
	adapterName = "corp-external"
	markerPath  = `C:\ProgramData\Vault443-QA\marker`
	marker      = "Vault443 isolated Windows fixture"
)

func protected(path string, private bool) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if err = securefs.Check(info, current, 0, private && current == path); err != nil {
			return err
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
func guard() error {
	host, err := os.Hostname()
	if err != nil || (!strings.EqualFold(host, "vault443-win10") && !strings.EqualFold(host, "vault443-win11")) {
		return errors.New("only the named Windows acceptance VMs may run this fixture")
	}
	exe, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(exe), imagePath) {
		return errors.New("fixture must be installed at its fixed protected path")
	}
	for _, path := range []string{imagePath, enginePath, driverPath} {
		if err = protected(path, false); err != nil {
			return fmt.Errorf("unsafe installed fixture dependency: %w", err)
		}
	}
	if err = protected(markerPath, false); err != nil {
		return err
	}
	text, err := os.ReadFile(markerPath)
	if err != nil || len(text) > 128 || strings.TrimSpace(string(text)) != marker {
		return errors.New("the protected acceptance marker is missing")
	}
	return nil
}
func validateConfig() error {
	path := filepath.Join(dataDir, "client.ovpn")
	if err := protected(path, true); err != nil {
		return err
	}
	text, err := os.ReadFile(path)
	if err != nil || len(text) > 128<<10 {
		return errors.New("invalid bounded fixture config")
	}
	allowed := map[string]bool{}
	for _, line := range []string{
		"client", "proto udp", "remote 192.0.2.1 1194", "dev tun", "nobind", "persist-key",
		"remote-cert-tls server", "verify-x509-name vpn.e2e.invalid name", "tls-version-min 1.2",
		"data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "tun-mtu 1400", "verb 3",
		"windows-driver wintun", "dev-node corp-external", "disable-dco", "script-security 1",
		"route-method ipapi", "redirect-gateway def1 ipv6", "redirect-gateway ipv6 !ipv4",
	} {
		allowed[line] = true
	}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(text)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if section != "" {
			if line == "</"+section+">" {
				section = ""
			}
			continue
		}
		if line == "<ca>" || line == "<cert>" || line == "<key>" {
			section = strings.Trim(line, "<>")
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !allowed[line] {
			return errors.New("fixture config contains a non-allowlisted directive")
		}
	}
	if err = scanner.Err(); err != nil || section != "" {
		return errors.New("malformed fixture config")
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if err := guard(); err != nil {
		return err
	}
	if len(os.Args) == 2 && (os.Args[1] == "--install" || os.Args[1] == "--uninstall") {
		if !windows.GetCurrentProcessToken().IsElevated() {
			return errors.New("explicit administrator approval is required")
		}
		return configure(os.Args[1] == "--install")
	}
	if len(os.Args) != 1 {
		return errors.New("only --install/--uninstall or the SCM service entry are supported")
	}
	service, err := svc.IsWindowsService()
	if err != nil || !service {
		return errors.New("start this fixture through Windows SCM")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("the fixture service requires LocalSystem")
	}
	return svc.Run(serviceName, handler{})
}
func configure(install bool) error {
	scm, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	if install {
		if err = validateConfig(); err != nil {
			return err
		}
		s, err := scm.CreateService(serviceName, imagePath, mgr.Config{DisplayName: "Vault443 external OpenVPN acceptance fixture", StartType: mgr.StartManual, ServiceStartName: "LocalSystem", Dependencies: []string{"nsi"}})
		if err != nil {
			return err
		}
		defer s.Close()
		return nil // Deliberately do not connect or change networking on install.
	}
	s, err := scm.OpenService(serviceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(cfg.BinaryPathName)
	if err != nil || len(args) != 1 || !strings.EqualFold(args[0], imagePath) {
		return errors.New("refusing to remove a differently configured service")
	}
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State != svc.Stopped {
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
		deadline := time.Now().Add(30 * time.Second)
		for state.State != svc.Stopped {
			if time.Now().After(deadline) {
				return errors.New("fixture did not stop; retained service and files")
			}
			time.Sleep(150 * time.Millisecond)
			state, err = s.Query()
			if err != nil {
				return err
			}
		}
	}
	return s.Delete()
}

type handler struct{}

func (handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 20000}
	err := serve(requests, status)
	if err != nil {
		log.Print(err)
		return true, 1
	}
	return false, 0
}
func serve(requests <-chan svc.ChangeRequest, status chan<- svc.Status) error {
	if err := validateConfig(); err != nil {
		return err
	}
	output, err := securefs.OpenFile(filepath.Join(dataDir, "fixture-service.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	log.SetOutput(output)
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if strings.EqualFold(iface.Alias(), adapterName) {
			return errors.New("refusing to adopt an existing external adapter")
		}
	}
	library, err := windows.LoadLibraryEx(driverPath, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return err
	}
	defer windows.FreeLibrary(library)
	create, err := windows.GetProcAddress(library, "WintunCreateAdapter")
	if err != nil {
		return err
	}
	closeAdapter, err := windows.GetProcAddress(library, "WintunCloseAdapter")
	if err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(adapterName)
	kind, _ := windows.UTF16PtrFromString("OpenVPN Wintun")
	adapter, _, callErr := syscall.SyscallN(create, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(kind)), 0)
	if adapter == 0 {
		return callErr
	}
	defer syscall.SyscallN(closeAdapter, adapter)
	// The official 2.6.23 manual and win32_signal_open use a manual-reset named
	// event, initially clear. Signaling it requests normal OpenVPN termination.
	eventName := fmt.Sprintf(`Global\CorpExternalOpenVPNFixture-%d-%d`, os.Getpid(), time.Now().UnixNano())
	event16, _ := windows.UTF16PtrFromString(eventName)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return err
	}
	event, err := windows.CreateEvent(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, 1, 0, event16)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	cmd := exec.Command(enginePath, "--config", filepath.Join(dataDir, "client.ovpn"), "--service", eventName, "0", "--log-append", filepath.Join(dataDir, "openvpn.log"))
	cmd.Dir = filepath.Dir(enginePath)
	var child core.Process
	if err = child.StartInstalled(context.Background(), cmd); err != nil {
		return err
	}
	defer child.StopContext(context.Background())
	log.Printf("started external OpenVPN pid=%d adapter=%s", cmd.Process.Pid, adapterName)
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 25000}
				if err = windows.SetEvent(event); err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				err = child.WaitContext(ctx)
				cancel()
				if err != nil {
					return errors.New("OpenVPN graceful event stop timed out; Job Object cleanup follows")
				}
				log.Print("external OpenVPN stopped after exit event; adapter released")
				return nil
			}
		case <-ticker.C:
			if !child.Alive() {
				return errors.New("external OpenVPN exited unexpectedly; inspect protected openvpn.log")
			}
		}
	}
}
