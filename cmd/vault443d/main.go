package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	app "vault443"
	"vault443/internal/ipc"
	"vault443/internal/journal"
	"vault443/internal/network"
	"vault443/internal/profiles"
	"vault443/internal/service"
	"vault443/internal/store"
	"vault443/internal/worknet"
	"vault443/internal/workvpn"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	version := flag.Bool("version", false, "print the Vault 443 release version and exit")
	stateDir := flag.String("state-dir", "/var/lib/vault443", "root-owned private state directory")
	runtimeDir := flag.String("runtime-dir", "/run/vault443", "private runtime directory")
	xray := flag.String("xray", "/usr/lib/vault443/xray", "packaged Xray executable")
	check := flag.Bool("check", false, "inspect configuration without writes, D-Bus or network changes")
	dry := flag.Bool("dry-run", false, "alias for the side-effect-free check mode")
	checkProfile := flag.Bool("check-profile", false, "read bounded VLESS links from stdin and print a redacted preview")
	bootGuard := flag.Bool("boot-guard", false, "arm persisted boot/recovery protection before networking; no D-Bus or connection")
	releaseNetwork := flag.Bool("release-network", false, "root maintenance: after stopping daemon, clear desired/boot sessions and release owned networking")
	openVPNEvent := flag.Bool("openvpn-event", false, "internal authenticated OpenVPN event handler")
	flag.Parse()
	if *openVPNEvent {
		return worknet.RunEventHelper()
	}
	if *version {
		fmt.Printf("Vault 443 %s\n", app.Version())
		return nil
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if !filepath.IsAbs(*stateDir) || !filepath.IsAbs(*runtimeDir) || !filepath.IsAbs(*xray) {
		return fmt.Errorf("daemon paths must be absolute")
	}
	if (*bootGuard || *releaseNetwork) && (*check || *dry || *checkProfile) || (*bootGuard && *releaseNetwork) {
		return fmt.Errorf("maintenance operations cannot be combined with each other or check modes")
	}
	if *check || *dry || *checkProfile {
		var report interface{}
		if *checkProfile {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, profiles.MaxBytes+1))
			if err != nil {
				return fmt.Errorf("cannot read profiles from stdin")
			}
			report = profiles.PreviewText(string(b), nil)
		} else {
			_, err := os.Stat(*xray)
			report = map[string]interface{}{"mode": "check", "networkMutations": false, "stateDir": *stateDir, "runtimeDir": *runtimeDir, "xrayPath": *xray, "xrayPresent": err == nil}
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install the system service first; the GUI runs without root")
	}
	st, err := store.OpenExclusive(*stateDir, false)
	if err != nil {
		return err
	}
	defer st.Close()
	runtime := network.New(network.Config{StateDir: *stateDir, RuntimeDir: *runtimeDir, XrayPath: *xray, DryRun: false})
	workStore, err := workvpn.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("cannot open private work VPN store: %w", err)
	}
	helper, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate the packaged OpenVPN event handler")
	}
	workRuntime := worknet.New(worknet.Config{StateDir: *stateDir, RuntimeDir: *runtimeDir, EventHelperPath: helper}, runtime)
	s := service.New(st, runtime)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if *releaseNetwork {
		releaseCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		if err := workStore.Update(func(st *workvpn.State) error { st.Desired = nil; return nil }); err != nil {
			return err
		}
		if err := workRuntime.Release(releaseCtx); err != nil {
			return err
		}
		return s.ReleaseNetwork(releaseCtx)
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Errorf("cannot read system boot identity")
	}
	workState := workStore.Snapshot()
	initCtx, stopInit := context.WithTimeout(ctx, 20*time.Second)
	err = workRuntime.Initialize(initCtx, strings.TrimSpace(string(bootID)), workState.BootID == strings.TrimSpace(string(bootID)) && len(workState.Desired) > 0)
	stopInit()
	if err != nil {
		return fmt.Errorf("work VPN protection could not be initialized: %w", err)
	}
	var desiredWorkIDs []string
	if workState.BootID == strings.TrimSpace(string(bootID)) {
		for _, d := range workState.Desired {
			desiredWorkIDs = append(desiredWorkIDs, d.ProfileID)
		}
	}
	pruneCtx, stopPrune := context.WithTimeout(ctx, 20*time.Second)
	err = workRuntime.RetainDesired(pruneCtx, desiredWorkIDs)
	stopPrune()
	if err != nil {
		return fmt.Errorf("work VPN cleanup after restart is incomplete: %w", err)
	}
	if *bootGuard {
		guardCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		defer stop()
		return s.BootGuard(guardCtx, strings.TrimSpace(string(bootID)))
	}
	// Early protection and explicit root cleanup must work even when journal
	// storage is damaged or full. Only the ordinary daemon requires its history.
	logs, err := journal.Open(filepath.Join(*stateDir, "journal"))
	if err != nil {
		return fmt.Errorf("cannot open private connection journal: %w", err)
	}
	defer logs.Close()
	s = service.New(st, runtime, logs)
	s.AttachWork(workStore, workRuntime)
	defer func() {
		cancel()
		stopWork, doneWork := context.WithTimeout(context.Background(), 15*time.Second)
		defer doneWork()
		s.StopWork(stopWork)
	}()
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("cannot connect to the system bus")
	}
	defer conn.Close()
	// Resolve reboot/restart intent before exporting mutable methods. A client
	// must not start a session that startup would then replace with the boot profile.
	if err = s.Start(ctx, strings.TrimSpace(string(bootID))); err != nil {
		log.Print("Startup protection is not ready; the supervisor will retry")
	}
	if err = s.StartWork(ctx, strings.TrimSpace(string(bootID))); err != nil {
		return fmt.Errorf("work VPN startup could not be restored: %w", err)
	}
	if err = ipc.Serve(ctx, conn, s); err != nil {
		return err
	}
	go s.RunSubscriptions(ctx)
	s.Run(ctx)
	// Do not call Disconnect on daemon termination: an unexpected supervisor
	// restart must preserve desired state and the crash-persistent kill switch.
	return nil
}
