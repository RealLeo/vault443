#!/usr/bin/env python3
"""Host controller for the fixed isolated inbound WFP capture; run with VM access."""
import argparse,json,re,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--machine',choices=['win10','win11'],required=True);p.add_argument('--label',required=True);p.add_argument('--backend',required=True);a=p.parse_args()
if not re.fullmatch(r'[a-z0-9-]{1,40}',a.label) or not re.fullmatch(r'[a-f0-9]{64}',a.backend):raise SystemExit('Invalid identity')
repo=Path(__file__).resolve().parents[2];out=repo/'dist/windows'/('native-'+a.machine);out.mkdir(exist_ok=True)
def run(argv,report=None,allow=False):
    r=subprocess.run(argv,cwd=repo,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=95)
    if report:(out/(a.label+'-'+report)).write_text(r.stdout)
    if r.returncode and not allow:raise RuntimeError('Test command failed; see '+str(report)+'; stderr='+r.stderr[-600:])
    return r

def ps(code,report=None,allow=False):return run(['python3','scripts/windows/vm.py','ps',a.machine,code],report,allow)
def ssh(code,report=None):return run(['python3','scripts/windows/fixture_vm.py','ssh',code],report)
def last_json(s):
    for line in reversed(s.splitlines()):
        try:return json.loads(line)
        except json.JSONDecodeError:continue
    raise ValueError('No result JSON')
try:
    status=json.loads(ps("$s=Get-CimInstance Win32_Service | Where-Object Name -eq Vault443;@{pid=$s.ProcessId;state=$s.State;sha=(Get-FileHash 'C:\\Program Files\\Vault443\\vault443d.exe' -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json",'initial.json').stdout)
    if status['state']!='Running' or status['sha']!=a.backend:raise RuntimeError('Backend identity mismatch')
    d=last_json(ps('& "C:\\Program Files\\Vault443QA\\main-matrix.ps1" -Phase disconnect','disconnect-result.txt').stdout)
    if not d['passed']:raise RuntimeError('Disconnect failed')
    r=ps('$p=Start-Process -FilePath "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File","C:\\Users\\Public\\Vault443Exchange\\inbound-guard.ps1","-Mode","server","-DurationSeconds","180") -WindowStyle Hidden -PassThru;@{pid=$p.Id}|ConvertTo-Json','server-start.json')
    pid=json.loads(r.stdout)['pid'];print('listener starting',flush=True)
    for i in range(8):
        r=ps('& "C:\\Users\\Public\\Vault443Exchange\\inbound-guard.ps1" -Mode readiness','readiness.json',True)
        if not r.returncode:
            ready=json.loads(r.stdout)
            if ready['ready'] and ready['processId']==pid:break
        time.sleep(1)
    else:raise RuntimeError('Listener readiness failed')
    baseline=json.loads(ssh('sudo python3 /home/vaultfixture/inbound-client.py --offlink allowed','baseline.json').stdout)
    if not baseline['passed']:raise RuntimeError('Positive baseline failed')
    print('baseline 8/8 PASS',flush=True)
    remote='/home/vaultfixture/'+a.label
    ssh('sudo systemd-run --unit=vault443-inbound-capture --collect --property=RuntimeMaxSec=85 /usr/bin/tcpdump -i fixture0 -nn -s 0 -U -w '+remote+'.pcap "host 192.0.2.2 or host 2001:db8:44::2" && sudo systemd-run --unit=vault443-inbound-hold --collect --property=RuntimeMaxSec=75 /bin/sh -c "python3 /home/vaultfixture/inbound-client.py --kind hold --seconds 60 > '+remote+'-hold.jsonl"')
    time.sleep(3)
    c=last_json(ps('& "C:\\Program Files\\Vault443QA\\main-matrix.ps1" -Phase connect -Protocol outline -ConnectTimeoutSeconds 35','connect-result.txt').stdout)
    if not c['passed']:raise RuntimeError('Arm failed; capture is NOT accepted')
    ps('[IO.File]::ReadAllText(\''+c['report']+'\')','arm-report.json')
    print('connected + guard armed',flush=True)
    armed=json.loads(ssh('sudo python3 /home/vaultfixture/inbound-client.py --offlink blocked','armed.json').stdout)
    print('armed probes passed='+str(armed['passed']),flush=True)
    # Hold must span at least ten seconds AFTER the connected observation.
    time.sleep(12)
    ssh('sudo systemctl stop vault443-inbound-hold.service vault443-inbound-capture.service || test ! -e /run/systemd/transient/vault443-inbound-capture.service')
    run(['python3','scripts/windows/fixture_vm.py','get',remote+'.pcap',str(out/(a.label+'.pcap'))])
    run(['python3','scripts/windows/fixture_vm.py','get',remote+'-hold.jsonl',str(out/(a.label+'-hold.jsonl'))])
    final=json.loads(ps('$s=Get-CimInstance Win32_Service | Where-Object Name -eq Vault443;@{pid=$s.ProcessId;state=$s.State}|ConvertTo-Json','final.json').stdout)
    if final['pid']!=status['pid']:raise RuntimeError('Service PID changed; capture is NOT accepted')
    run(['python3','tests/windows/analyze-inbound-pcap.py','--pcap',str(out/(a.label+'.pcap')),'--arm-report',str(out/(a.label+'-arm-report.json')),'--hold',str(out/(a.label+'-hold.jsonl')),'--baseline',str(out/(a.label+'-baseline.json')),'--probe-report',str(out/(a.label+'-armed.json')),'--output',str(out/(a.label+'-analysis.json'))])
    analysis=json.loads((out/(a.label+'-analysis.json')).read_text())
    print('acceptancePassed='+str(analysis['acceptancePassed']),flush=True)
    if not analysis['acceptancePassed']:raise SystemExit(1)
except BaseException:
    # Stop only the two fixed test units. No VM/app network cleanup is inferred.
    subprocess.run(['python3','scripts/windows/fixture_vm.py','ssh','sudo systemctl stop vault443-inbound-capture.service vault443-inbound-hold.service'],cwd=repo,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    raise
