package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	app "vault443"
	"vault443/internal/ipc"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/profiles"
	"vault443/internal/securefs"
	"vault443/internal/service"
	"vault443/internal/store"
	"vault443/internal/winplatform"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

const windowsServiceName = "Vault443"

type options struct {
	stateDir, runtimeDir, xray string
	maintenance                bool
}

func main() {
	if err := runWindows(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func runWindows() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	root := filepath.Join(os.Getenv("ProgramData"), "Vault443")
	version := flag.Bool("version", false, "print version")
	check := flag.Bool("check", false, "inspect without writes or network changes")
	dry := flag.Bool("dry-run", false, "alias for --check")
	profile := flag.Bool("check-profile", false, "read bounded profiles on stdin and print a redacted preview")
	install := flag.Bool("install-service", false, "install or update the LocalSystem service (administrator only)")
	uninstall := flag.Bool("uninstall-service", false, "release owned networking and remove the service (administrator only)")
	release := flag.Bool("release-network", false, "stop the service and release owned networking as LocalSystem (administrator only)")
	maintenance := flag.Bool("maintenance-release", false, "internal transient LocalSystem maintenance service")
	console := flag.Bool("console", false, "run in a LocalSystem diagnostic console")
	state := flag.String("state-dir", root, "private service state directory")
	runtime := flag.String("runtime-dir", filepath.Join(root, "runtime"), "private runtime directory")
	xray := flag.String("xray", filepath.Join(filepath.Dir(exe), "xray.exe"), "installed pinned Xray executable")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *version {
		fmt.Printf("Vault 443 %s\n", app.Version())
		return nil
	}
	if *profile {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, profiles.MaxBytes+1))
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(profiles.PreviewText(string(data), nil))
	}
	if *check || *dry {
		_, err := os.Stat(*xray)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "check", "platform": "windows", "networkMutations": false, "stateDir": *state, "runtimeDir": *runtime, "xrayPath": *xray, "xrayPresent": err == nil})
	}
	if !filepath.IsAbs(*state) || !filepath.IsAbs(*runtime) || !filepath.IsAbs(*xray) {
		return errors.New("service paths must be absolute")
	}
	if *install {
		return installWindowsService(exe)
	}
	if *uninstall || *release {
		return removeWindowsService(exe, *uninstall)
	}
	c := options{*state, *runtime, *xray, *maintenance}
	if *console {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return serveWindows(ctx, c, nil)
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isService {
		return errors.New("install the Windows service first; the interface runs without administrator rights")
	}
	name := windowsServiceName
	if *maintenance {
		name += "Maintenance"
	}
	return svc.Run(name, &serviceHandler{config: c})
}

type serviceHandler struct{ config options }

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 30000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serveWindows(ctx, h.config, ready) }()
	for {
		select {
		case <-ready:
			ready = nil
			status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						return true, 1
					}
					return false, 0
				case <-time.After(20 * time.Second):
					return true, 2
				}
			}
		}
	}
}
func serveWindows(ctx context.Context, c options, ready chan<- struct{}) (result error) {
	if _, err := securefs.Owner(false); err != nil {
		return err
	}
	st, err := store.OpenExclusive(c.stateDir, false)
	if err != nil {
		return err
	}
	defer st.Close()
	logPath := filepath.Join(c.stateDir, "service.log")
	if info, e := os.Lstat(logPath); e == nil && info.Size() > 1<<20 {
		if e = securefs.Replace(logPath, logPath+".previous"); e != nil {
			return e
		}
	}
	output, err := securefs.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND|securefs.NoFollow, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	log.SetOutput(output)
	// Registered before runtime cleanup, so its errors are included while this
	// protected log is still open. The SCM handler runs after output.Close.
	defer func() {
		if result != nil {
			log.Print(result)
		}
	}()
	// The runtime duplicates this protected descriptor; SCM panic/fatal stacks
	// survive without intercepting the panic or changing normal log rotation.
	if err = debug.SetCrashOutput(output, debug.CrashOptions{}); err != nil {
		return fmt.Errorf("cannot configure private Windows crash output: %w", err)
	}
	runtime := network.New(network.Config{StateDir: c.stateDir, RuntimeDir: c.runtimeDir, XrayPath: c.xray})
	p, err := runtime.Platform()
	if err != nil {
		return err
	}
	if err = p.RecoverSources(ctx); err != nil {
		return fmt.Errorf("temporary source network recovery failed: %w", err)
	}
	workStore, err := workvpn.Open(c.stateDir)
	if err != nil {
		return fmt.Errorf("cannot open private work VPN store: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	workRuntime := worknet.New(worknet.Config{StateDir: c.stateDir, RuntimeDir: c.runtimeDir, EventHelperPath: executable}, runtime)
	if c.maintenance {
		if err = st.Update(func(state *store.State) error { state.Desired = nil; state.Boot = nil; return nil }); err != nil {
			return err
		}
		if err = workStore.Update(func(state *workvpn.State) error { state.Desired = nil; return nil }); err != nil {
			return err
		}
		if err = workRuntime.Release(ctx); err != nil {
			return err
		}
		if err = runtime.Disconnect(ctx); err != nil {
			return err
		}
		if err = runtime.ReleaseExternal(ctx); err != nil {
			return err
		}
		if err = p.Routes.ClearExcept(nil); err != nil {
			return err
		}
		if err = p.DNS.Restore(); err != nil {
			return err
		}
		return p.Guard.ClearExcept(nil)
	}
	boot, err := winplatform.BootID()
	if err != nil {
		return err
	}
	workState := workStore.Snapshot()
	initialize, stopInitialize := context.WithTimeout(ctx, 20*time.Second)
	err = workRuntime.Initialize(initialize, boot, workState.BootID == boot && len(workState.Desired) > 0)
	stopInitialize()
	if err != nil {
		return fmt.Errorf("work VPN protection could not be initialized: %w", err)
	}
	var workIDs []string
	if workState.BootID == boot {
		for _, desired := range workState.Desired {
			workIDs = append(workIDs, desired.ProfileID)
		}
	}
	prune, stopPrune := context.WithTimeout(ctx, 20*time.Second)
	err = workRuntime.RetainDesired(prune, workIDs)
	stopPrune()
	if err != nil {
		return fmt.Errorf("work VPN cleanup after restart is incomplete: %w", err)
	}
	logs, err := journal.Open(filepath.Join(c.stateDir, "journal"))
	if err != nil {
		return err
	}
	defer logs.Close()
	s := service.New(st, runtime, logs)
	s.AttachWork(workStore, workRuntime)
	defer func() {
		// Leave two seconds for SCM status delivery within its 20-second stop
		// deadline. Stop tunnel consumers before closing the main creator handle.
		stop, done := context.WithTimeout(context.Background(), 18*time.Second)
		defer done()
		s.StopWork(stop)
		result = errors.Join(result, runtime.Shutdown(stop))
	}()
	state := st.Snapshot()
	desired := state.Desired
	if state.BootID != boot {
		desired = state.Boot
	}
	if desired == nil {
		if err = runtime.Disconnect(ctx); err != nil {
			return err
		}
	}
	if err = p.DNS.Start(ctx); err != nil {
		return err
	}
	if err = s.Start(ctx, boot); err != nil {
		log.Print("Startup protection will be retried")
	}
	if err = s.StartWork(ctx, boot); err != nil {
		return fmt.Errorf("work VPN startup could not be restored: %w", err)
	}
	if err = ipc.ServePipe(ctx, s, c.stateDir); err != nil {
		return err
	}
	if ready != nil {
		close(ready)
	}
	go s.RunSubscriptions(ctx)
	s.Run(ctx)
	// Intent and persistent WFP protection survive normal stops and crashes.
	return nil
}
func administrativeSCM() (*mgr.Mgr, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("administrator approval is required")
	}
	return mgr.Connect()
}
func installWindowsService(exe string) error {
	m, err := administrativeSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	c := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: "Vault 443 VPN", Description: "Protected main and work VPN connections", StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem", Dependencies: []string{"BFE", "nsi"}}
	s, err := m.OpenService(windowsServiceName)
	if err == nil {
		defer s.Close()
		c.BinaryPathName = windows.EscapeArg(exe)
		if err = s.UpdateConfig(c); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(windowsServiceName, exe, c)
		if err != nil {
			return err
		}
		defer s.Close()
	}
	if err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}, {Type: mgr.ServiceRestart, Delay: 2 * time.Second}, {Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 86400); err != nil {
		return err
	}
	if err = s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State == svc.Running {
		return nil
	}
	return s.Start()
}
func stopService(s *mgr.Service) error {
	state, err := s.Query()
	if err != nil {
		return err
	}
	if state.State == svc.Stopped {
		return nil
	}
	if _, err = s.Control(svc.Stop); err != nil && err != windows.ERROR_SERVICE_NOT_ACTIVE {
		return err
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		state, err = s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("Windows service did not stop")
}
func removeWindowsService(exe string, uninstall bool) error {
	m, err := administrativeSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(windowsServiceName)
	if err == nil {
		defer s.Close()
		if err = stopService(s); err != nil {
			return err
		}
	} else if err != windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return err
	}
	maintenance, err := m.CreateService(windowsServiceName+"Maintenance", exe, mgr.Config{DisplayName: "Vault 443 network maintenance", StartType: mgr.StartManual, ServiceStartName: "LocalSystem"}, "--maintenance-release")
	if err != nil {
		return err
	}
	defer maintenance.Close()
	defer maintenance.Delete()
	if err = maintenance.Start(); err != nil {
		return err
	}
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		state, e := maintenance.Query()
		if e != nil {
			return e
		}
		if state.State == svc.Stopped {
			if state.Win32ExitCode != 0 {
				return errors.New("network restoration failed; service files must be retained")
			}
			if uninstall && s != nil {
				return s.Delete()
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("network maintenance did not finish; protection has been retained")
}
