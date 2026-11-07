package winplatform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"vault443/internal/securefs"
)

type nrptState struct {
	OwnerToken string `json:"ownerToken"`
	RuleGUID   string `json:"ruleGuid,omitempty"`
	Phase      string `json:"phase"`
}
type nrptRequest struct {
	Mode       string   `json:"mode"`
	OwnerToken string   `json:"ownerToken"`
	RuleGUID   string   `json:"ruleGuid"`
	Zones      []string `json:"zones"`
}
type nrptResponse struct {
	RuleGUID  string `json:"ruleGuid"`
	Effective bool   `json:"effective"`
	Missing   bool   `json:"missing"`
	Removed   bool   `json:"removed"`
	Conflicts []int  `json:"conflicts"`
	Failure   string `json:"failure"`
}
type nrptRunner func(context.Context, nrptRequest) (nrptResponse, error)
type nrptConflictError struct{ zones []string }

func (e *nrptConflictError) Error() string {
	zones := e.zones
	if len(zones) > 8 {
		zones = zones[:8]
	}
	return "foreign Windows NRPT policy shadows protected DNS zones: " + strings.Join(zones, ", ")
}
func validNRPTGUID(text string) bool {
	guid, err := windows.GUIDFromString(text)
	return err == nil && guid != (windows.GUID{})
}
func validateNRPTState(state *nrptState) error {
	if state == nil {
		return nil
	}
	if !validNRPTGUID(state.OwnerToken) || (state.RuleGUID != "" && !validNRPTGUID(state.RuleGUID)) ||
		(state.Phase != "creating" && state.Phase != "active" && state.Phase != "removing") ||
		(state.Phase == "active" && state.RuleGUID == "") {
		return errors.New("invalid private Windows NRPT recovery identity")
	}
	return nil
}
func copyDNSPlans(plans map[string]DNSPlan) map[string]DNSPlan {
	result := make(map[string]DNSPlan, len(plans))
	for key, plan := range plans {
		plan.Domains = append([]string(nil), plan.Domains...)
		plan.Servers = append(plan.Servers[:0:0], plan.Servers...)
		result[key] = plan
	}
	return result
}
func (d *DNS) replacePlansLocked(next map[string]DNSPlan, uplink winipcfg.LUID) error {
	if d.blocked == nil {
		d.blocked = map[string]bool{}
	}
	for key, plan := range next {
		if previous, ok := d.plans[key]; !ok || !reflect.DeepEqual(previous, plan) {
			d.blocked[key] = true
		}
	}
	for key := range d.blocked {
		if _, ok := next[key]; !ok {
			delete(d.blocked, key)
		}
	}
	d.plans = next // Keep new protected zones even if provisioning/NRPT fails.
	if len(next) == 0 {
		if d.started {
			return d.restore()
		}
		return nil // Startup groups are assembled before the listener is reserved.
	}
	if uplink != 0 {
		if err := d.provision(uplink); err != nil {
			return err
		}
	}
	if !d.started {
		return nil
	}
	return d.activatePlansLocked(context.Background())
}
func nrptZones(plans map[string]DNSPlan) ([]string, error) {
	set := map[string]bool{}
	for key, plan := range plans {
		if key != "main" && plan.Default {
			set["."] = true
		}
		for _, raw := range plan.Domains {
			if strings.TrimPrefix(raw, "~") == "." {
				set["."] = true
				continue
			}
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(raw, "~"), "."))
			if domain == "" || len(domain) > 253 {
				return nil, errors.New("invalid protected Windows DNS zone")
			}
			for _, label := range strings.Split(domain, ".") {
				if len(label) == 0 || len(label) > 63 {
					return nil, errors.New("invalid protected Windows DNS zone")
				}
				for _, c := range label {
					if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
						return nil, errors.New("invalid protected Windows DNS zone")
					}
				}
			}
			set[domain] = true
		}
	}
	if len(set) > 4096 {
		return nil, errors.New("Windows DNS zone limit exceeded")
	}
	result := make([]string, 0, len(set))
	for zone := range set {
		result = append(result, zone)
	}
	sort.Strings(result)
	return result, nil
}
func (d *DNS) activatePlansLocked(ctx context.Context) error {
	err := d.ensureNRPTLocked(ctx)
	if err != nil {
		if !d.nrptReady {
			d.blockAll = true
			return err
		}
		var conflict *nrptConflictError
		if errors.As(err, &conflict) {
			for key, plan := range d.plans {
				zones, e := nrptZones(map[string]DNSPlan{key: plan})
				if e != nil {
					d.blocked[key] = true
					continue
				}
				for _, zone := range zones {
					for _, denied := range conflict.zones {
						if zone == denied {
							d.blocked[key] = true
						}
					}
				}
			}
		}
		return err // Unchanged healthy plans keep answering under verified NRPT.
	}
	if err = d.restoreLegacyLocked(); err != nil {
		return err
	}
	if d.physical != 0 {
		if err = d.provision(d.physical); err != nil {
			return err
		}
	}
	d.blocked = map[string]bool{}
	d.blockAll = false
	return nil
}
func (d *DNS) ensureNRPTLocked(parent context.Context) error {
	zones, err := nrptZones(d.plans)
	if err != nil {
		return err
	}
	data, err := json.Marshal(d.plans)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%x", sha256.Sum256(data))
	if d.nrptReady && key == d.nrptKey {
		if d.nrptConflict != nil {
			return d.nrptConflict
		}
		return nil
	}
	d.nrptReady = false
	if d.nrpt == nil {
		guid, e := windows.GenerateGUID()
		if e != nil {
			return e
		}
		d.nrpt = &nrptState{OwnerToken: strings.ToLower(guid.String()), Phase: "creating"}
	}
	if d.nrpt.RuleGUID == "" {
		d.nrpt.Phase = "creating"
		if err = d.saveLocked(); err != nil {
			return err
		} // Also retry the durable boundary after a previous write failure.
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	run := d.nrptRun
	if run == nil {
		run = runNRPTCommand
	}
	request := nrptRequest{Mode: "ensure", OwnerToken: d.nrpt.OwnerToken, RuleGUID: d.nrpt.RuleGUID, Zones: zones}
	response, err := run(ctx, request)
	if err != nil {
		return err
	}
	if response.Failure != "" {
		return fmt.Errorf("Windows NRPT verification failed: %s", response.Failure)
	}
	if response.Missing {
		// Re-creation needs the same write-before-Add boundary as first install.
		// A crash after Add must never retain an obsolete known rule GUID.
		d.nrpt.RuleGUID, d.nrpt.Phase = "", "creating"
		if err = d.saveLocked(); err != nil {
			return err
		}
		request.RuleGUID = ""
		response, err = run(ctx, request)
		if err != nil {
			return err
		}
	}
	if response.Failure != "" || !response.Effective || !validNRPTGUID(response.RuleGUID) {
		return errors.New("owned Windows NRPT rule is not effective; recovery identity retained")
	}
	d.nrpt.RuleGUID, d.nrpt.Phase = response.RuleGUID, "active"
	if err = d.saveLocked(); err != nil {
		return err
	}
	d.nrptConflict = nil
	if len(response.Conflicts) > 0 {
		conflict := &nrptConflictError{}
		for _, index := range response.Conflicts {
			if index < 0 || index >= len(zones) {
				return errors.New("invalid NRPT conflict response")
			}
			conflict.zones = append(conflict.zones, zones[index])
		}
		d.nrptConflict = conflict
	}
	d.nrptReady, d.nrptKey, d.blockAll = true, key, false
	if d.nrptConflict != nil {
		return d.nrptConflict
	}
	return nil
}
func (d *DNS) removeNRPTLocked(parent context.Context) error {
	if d.nrpt == nil {
		return nil
	}
	d.nrpt.Phase = "removing"
	if err := d.saveLocked(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	run := d.nrptRun
	if run == nil {
		run = runNRPTCommand
	}
	response, err := run(ctx, nrptRequest{Mode: "remove", OwnerToken: d.nrpt.OwnerToken, RuleGUID: d.nrpt.RuleGUID})
	if err != nil {
		return err
	}
	if response.Failure != "" || !response.Removed {
		return errors.New("owned Windows NRPT removal could not be verified; recovery identity retained")
	}
	d.nrptReady = false
	return nil // Identity is cleared only after all legacy journal cleanup succeeds.
}

type nrptOutput struct {
	bytes.Buffer
	limit int
}

func (b *nrptOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > b.limit {
		return 0, errors.New("bounded NRPT command output exceeded")
	}
	return b.Buffer.Write(data)
}
func runNRPTCommand(ctx context.Context, request nrptRequest) (nrptResponse, error) {
	var result nrptResponse
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return result, errors.New("Windows DNS policy requires LocalSystem")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return result, err
	}
	executable := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	for path := executable; ; path = filepath.Dir(path) {
		info, e := os.Lstat(path)
		if e != nil {
			return result, e
		}
		if e = securefs.Check(info, path, 0, false); e != nil {
			return result, e
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	input, err := json.Marshal(request)
	if err != nil || len(input) > 2<<20 {
		return result, errors.New("bounded NRPT command input exceeded")
	}
	encoded := utf16.Encode([]rune(nrptPowerShell))
	script := make([]byte, 2*len(encoded))
	for i, c := range encoded {
		binary.LittleEndian.PutUint16(script[2*i:], c)
	}
	cmd := exec.CommandContext(ctx, executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.StdEncoding.EncodeToString(script))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.WaitDelay = time.Second
	root := filepath.Dir(system)
	cmd.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "PATH=" + system, "PSModulePath=" + filepath.Join(filepath.Dir(executable), "Modules"), "TEMP=" + filepath.Join(root, "Temp"), "TMP=" + filepath.Join(root, "Temp")}
	cmd.Stdin = bytes.NewReader(input)
	output := &nrptOutput{limit: 128 << 10}
	stderr := &nrptOutput{limit: 16 << 10}
	cmd.Stdout, cmd.Stderr = output, stderr
	// The PS child must die with its supervisor even if the Go context timer
	// disappears in a service crash. The shared WMI provider is not our child.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return result, err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return result, err
	}
	if err = cmd.Start(); err != nil {
		return result, errors.New("cannot start the fixed Windows NRPT command")
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		cmd.Process.Kill()
		stopped := make(chan struct{})
		go func() { cmd.Wait(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
		}
		return result, errors.New("cannot protect the Windows NRPT command with its supervisor Job Object")
	}
	if err = cmd.Wait(); err != nil {
		return result, errors.New("fixed Windows NRPT command failed or exceeded its 15-second deadline")
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil {
		return result, errors.New("invalid bounded Windows NRPT response")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return result, errors.New("unexpected Windows NRPT response data")
	}
	return result, nil
}

// Fixed local-only cmdlets; JSON input supplies identity/data, never commands,
// paths, GPOs, servers, scripts or executable arguments selected by a profile.
const nrptPowerShell = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$out=[ordered]@{ruleGuid='';effective=$false;missing=$false;removed=$false;conflicts=@();failure=''}
try {
 Import-Module (Join-Path $PSHOME 'Modules\DnsClient\DnsClient.psd1') -ErrorAction Stop
 $text=[Console]::In.ReadToEnd()
 if($text.Length -gt 2097152){throw 'input_limit'}
 $r=$text|ConvertFrom-Json
 $token=[guid]::Empty
 if($r.mode -notin @('ensure','remove') -or ![guid]::TryParse([string]$r.ownerToken,[ref]$token) -or $token -eq [guid]::Empty){throw 'invalid_identity'}
 $display='Vault443 DNS '+[string]$r.ownerToken
 $comment='Vault443 local DNS coordinator '+[string]$r.ownerToken
 function Rules {
  $items=@(Get-DnsClientNrptRule)
  if($items.Count -gt 512){throw 'rule_limit'}
  return $items
 }
 function Loopback($rule){
  $servers=@((@($rule.NameServers)-join ';') -split '[,;\s]+'|Where-Object{$_}|ForEach-Object{[Net.IPAddress]::Parse($_).ToString()}|Sort-Object -Unique)
  return $servers.Count -eq 2 -and $servers -contains '127.0.0.1' -and $servers -contains '::1'
 }
 function Owned($rule){
  if($rule.DisplayName -cne $display -or $rule.Comment -cne $comment -or @($rule.Namespace).Count -ne 1 -or $rule.Namespace[0] -ne '.' -or !(Loopback $rule)){throw 'owned_rule_changed'}
  $id=[guid]::Empty
  if(![guid]::TryParse([string]$rule.Name,[ref]$id) -or $id -eq [guid]::Empty){throw 'invalid_rule_guid'}
 }
 $rules=@(Rules)
 $markers=@($rules|Where-Object{$_.DisplayName -ceq $display -or $_.Comment -ceq $comment})
 if($markers.Count -gt 1){throw 'ambiguous_owner'}
 $own=$null
 if($r.ruleGuid){
  $id=[guid]::Empty
  if(![guid]::TryParse([string]$r.ruleGuid,[ref]$id)){throw 'invalid_rule_guid'}
  $exact=@($rules|Where-Object{[string]$_.Name -ieq [string]$r.ruleGuid})
  if($exact.Count -gt 1){throw 'ambiguous_owner'}
  if($exact.Count){$own=$exact[0];Owned $own}
  elseif($markers.Count){throw 'owned_rule_guid_changed'}
 }elseif($markers.Count){$own=$markers[0];Owned $own}
 if($r.mode -eq 'remove'){
  if($null -ne $own){
   $again=@(Get-DnsClientNrptRule -Name $own.Name)
   if($again.Count -ne 1){throw 'owned_rule_changed'}
   Owned $again[0]
   Remove-DnsClientNrptRule -Name $own.Name -Force -Confirm:$false
  }
  $remaining=@(Rules|Where-Object{($_.DisplayName -ceq $display -or $_.Comment -ceq $comment) -or ($r.ruleGuid -and [string]$_.Name -ieq [string]$r.ruleGuid)})
  if($remaining.Count){throw 'removal_not_verified'}
  $out.removed=$true
 }else{
  if(@($r.zones).Count -gt 4096){throw 'zone_limit'}
  foreach($zone in @($r.zones)){if($zone -ne '.' -and ([string]$zone).Length -gt 253){throw 'zone_limit'}}
  if($null -eq $own -and $r.ruleGuid){$out.missing=$true}
  else{
   $foreign=@($rules|Where-Object{(@($_.Namespace) -contains '.') -and ($null -eq $own -or $_.Name -ine $own.Name)})
   if($foreign.Count){throw 'foreign_catchall'}
   $effective=@(Get-DnsClientNrptPolicy -Effective)
   if($effective.Count -gt 512){throw 'policy_limit'}
   if($null -eq $own -and @($effective|Where-Object{@($_.Namespace) -contains '.'}).Count){throw 'foreign_catchall'}
   if($null -eq $own){
    $own=Add-DnsClientNrptRule -Namespace '.' -NameServers @('127.0.0.1','::1') -DisplayName $display -Comment $comment -PassThru -Confirm:$false
    if($null -eq $own){throw 'add_identity_missing'}
    Owned $own
   }
   $out.ruleGuid=[string]$own.Name
   $rules=@(Rules)
   $markers=@($rules|Where-Object{$_.DisplayName -ceq $display -or $_.Comment -ceq $comment})
   if($markers.Count -ne 1 -or $markers[0].Name -ine $own.Name){throw 'ambiguous_owner'}
   Owned $markers[0]
   if(@($rules|Where-Object{(@($_.Namespace) -contains '.') -and $_.Name -ine $own.Name}).Count){throw 'foreign_catchall'}
   $effective=@(Get-DnsClientNrptPolicy -Effective)
   if($effective.Count -gt 512){throw 'policy_limit'}
   $all=@($effective|Where-Object{@($_.Namespace) -contains '.'})
   if($all.Count -ne 1 -or !(Loopback $all[0])){throw 'owned_rule_not_effective'}
   $out.effective=$true
   $conflicts=New-Object 'System.Collections.Generic.HashSet[int]'
   for($i=0;$i -lt @($r.zones).Count;$i++){
    $zone=[string]$r.zones[$i]
    foreach($policy in $effective){foreach($raw in @($policy.Namespace)){
     $ns=([string]$raw).ToLowerInvariant().TrimEnd('.')
     if(!$ns){continue}
     $suffix=$ns.StartsWith('.') -or $ns.StartsWith('*.')
     $ns=$ns.TrimStart('*').TrimStart('.')
     if($zone -eq '.' -or $ns -eq $zone -or $ns.EndsWith('.'+$zone) -or ($suffix -and $zone.EndsWith('.'+$ns))){[void]$conflicts.Add($i)}
    }}
   }
   $out.conflicts=@($conflicts|Sort-Object)
  }
 }
}catch{
 $known=@('input_limit','invalid_identity','rule_limit','owned_rule_changed','invalid_rule_guid','ambiguous_owner','owned_rule_guid_changed','removal_not_verified','zone_limit','foreign_catchall','policy_limit','add_identity_missing','owned_rule_not_effective')
 $message=[string]$_.Exception.Message
 $out.failure=if($message -in $known){$message}else{'command_error'}
 $out.effective=$false
}
$out|ConvertTo-Json -Compress -Depth 5
`
