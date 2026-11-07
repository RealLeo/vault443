#!/usr/bin/env python3
"""R8 Win10/Win11 partial-peer QA orchestration. REVIEW before escalated execution."""
import argparse
import datetime as dt
import hashlib
import re
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import uuid

def backend_sha(value):
    if not re.fullmatch(r'[a-f0-9]{64}', value):
        raise argparse.ArgumentTypeError('expected lowercase SHA-256')
    return value

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--machine', choices=('win10', 'win11'), required=True)
parser.add_argument('--backend', type=backend_sha, default='4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50')
args = parser.parse_args()
REPO = Path(__file__).resolve().parents[2]
OUT = REPO / 'dist/windows' / ('native-' + args.machine + '-r8') / 'r8-outputs/partial'
GUEST_SCRIPT = r'C:\Users\Public\Vault443Exchange\r8-partial.ps1'
GUEST_REPORTS = r'C:\Users\Public\Vault443Exchange\r8-outputs\partial'
SCRIPT_SHA = hashlib.sha256((Path(__file__).with_name('r8-partial.ps1')).read_bytes()).hexdigest()
TOKEN = str(uuid.uuid4())
STAMP = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
META = OUT / ('r8-partial-host-' + STAMP + '.json')
STATE = {'schema': 1, 'machine': args.machine, 'backendSHA': args.backend, 'scriptSHA': SCRIPT_SHA, 'token': TOKEN, 'startedUTC': STAMP, 'passed': False,
         'completed': False, 'cleanup': None, 'blocked': None, 'recovered': None,
         'errors': [], 'noConnectOrAppChanges': True, 'captureManagedExternally': True}

# Fixed guest-only program. All command operands below are literals or a GUID token.
LINUX = r'''
import json,os,socket,stat,subprocess,sys
from pathlib import Path
act,token=sys.argv[1:]
import uuid
if str(uuid.UUID(token))!=token:raise RuntimeError('InvalidOwnerToken')
TABLE='vault443_r8_partial';J=Path('/run/vault443-r8-partial-owner.json')
if os.geteuid()!=0 or socket.gethostname()!='vault443-fixture':raise RuntimeError('NamedRootFixtureRequired')
m=Path('/etc/vault443-fixture-guest');s=m.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or m.read_text().strip()!='isolated Windows VPN acceptance fixture':raise RuntimeError('FixtureMarkerRequired')
if Path('/sys/class/net/fixture0/address').read_text().strip().replace(':','').lower()!='080027443002':raise RuntimeError('FixtureMACChanged')
def cmd(args,check=True):return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=check,timeout=12)
def table():
 tables=json.loads(cmd(['nft','-j','list','tables']).stdout)['nftables']
 if not any(x.get('table',{}).get('family')=='inet' and x.get('table',{}).get('name')==TABLE for x in tables):return None
 return json.loads(cmd(['nft','-j','list','table','inet',TABLE]).stdout)['nftables']
def matches(chain):
 incoming=chain=='input';port='dport' if incoming else 'sport'
 src,dst=('192.0.2.2','192.0.2.1') if incoming else ('192.0.2.1','192.0.2.2')
 return [dict(match=dict(op='==',left=dict(meta=dict(key='iifname' if incoming else 'oifname')),right='fixture0')),
 dict(match=dict(op='==',left=dict(payload=dict(protocol='ip',field='saddr')),right=src)),
 dict(match=dict(op='==',left=dict(payload=dict(protocol='ip',field='daddr')),right=dst)),
 dict(match=dict(op='==',left=dict(payload=dict(protocol='udp',field=port)),right=51822))]
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def inspect(items):
 objects=[x for x in items if 'metainfo' not in x]
 if len(objects)!=5 or sum('table' in x for x in objects)!=1 or sum('chain' in x for x in objects)!=2 or sum('rule' in x for x in objects)!=2:raise RuntimeError('ForeignObjectsRefuseCleanup')
 t=next(x['table'] for x in objects if 'table' in x)
 if t.get('family')!='inet' or t.get('name')!=TABLE:raise RuntimeError('ForeignTableIdentity')
 counters={}
 for name in ('input','output'):
  chains=[x['chain'] for x in objects if 'chain' in x and x['chain'].get('name')==name]
  rules=[x['rule'] for x in objects if 'rule' in x and x['rule'].get('chain')==name]
  if len(chains)!=1 or len(rules)!=1:raise RuntimeError('ForeignChainOrRule')
  c,r=chains[0],rules[0]
  if c.get('family')!='inet' or c.get('table')!=TABLE or c.get('hook')!=name or c.get('type')!='filter' or c.get('prio')!=-10 or c.get('policy')!='accept':raise RuntimeError('ForeignChainPolicy')
  if r.get('family')!='inet' or r.get('table')!=TABLE or r.get('comment')!='Vault443R8Partial:'+token+':'+name:raise RuntimeError('ForeignRuleToken')
  rest=[];counts=[];drops=0
  for e in r['expr']:
   if 'counter' in e:counts.append(e['counter'])
   elif 'drop' in e:drops+=1
   elif e in [dict(match=dict(op='==',left=dict(meta=dict(key='l4proto')),right=v)) for v in ('udp',17)]+[dict(match=dict(op='==',left=dict(meta=dict(key='nfproto')),right='ipv4'))]:pass
   else:rest.append(e)
  if len(counts)!=1 or drops!=1 or sorted(map(canonical,rest))!=sorted(map(canonical,matches(name))):raise RuntimeError('ForeignRuleExpression')
  counters[name]={'packets':counts[0]['packets'],'bytes':counts[0]['bytes']}
 return counters
if act=='create':
 if J.exists() or J.is_symlink() or table() is not None:raise RuntimeError('PreexistingOwnerOrTableRefused')
 # Other DROP faults would invalidate isolation; this isolated fixture has no normal firewall drops.
 all_rules=json.loads(cmd(['nft','-j','list','ruleset']).stdout)['nftables']
 if any('rule' in x and any('drop' in e for e in x['rule'].get('expr',[])) for x in all_rules):raise RuntimeError('AnotherDropFaultPresent')
 fd=os.open(J,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump({'token':token,'table':TABLE,'machine':'vault443-fixture'},f);f.flush();os.fsync(f.fileno())
 batch='add table inet '+TABLE+'\n'
 for name in ('input','output'):
  batch+='add chain inet '+TABLE+' '+name+' { type filter hook '+name+' priority -10; policy accept; }\n'
  direction='iifname "fixture0" ip saddr 192.0.2.2 ip daddr 192.0.2.1 udp dport 51822' if name=='input' else 'oifname "fixture0" ip saddr 192.0.2.1 ip daddr 192.0.2.2 udp sport 51822'
  batch+='add rule inet '+TABLE+' '+name+' '+direction+' counter drop comment "Vault443R8Partial:'+token+':'+name+'"\n'
 p=subprocess.run(['nft','-f','-'],input=batch,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
 if p.returncode:raise RuntimeError('AtomicNFTCreateFailed')
 print(json.dumps({'created':True,'counters':inspect(table())}))
elif act=='cleanup':
 items=table()
 if not J.exists():
  if items is not None:raise RuntimeError('UnownedTableRefused')
  print(json.dumps({'cleaned':True,'nothingCreated':True}));sys.exit(0)
 s=J.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('ForeignJournalACL')
 owner=json.loads(J.read_text())
 if owner!={'token':token,'table':TABLE,'machine':'vault443-fixture'}:raise RuntimeError('ForeignJournalToken')
 counters=inspect(items) if items is not None else {}
 if items is not None:cmd(['nft','delete','table','inet',TABLE])
 if table() is not None:raise RuntimeError('TableRemovalNotConfirmed')
 J.unlink();print(json.dumps({'cleaned':True,'counters':counters}))
else:raise RuntimeError('FixedActionRequired')
'''

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def save():
    OUT.mkdir(parents=True, exist_ok=True)
    temp = META.with_suffix('.tmp')
    temp.write_text(json.dumps(STATE, indent=2) + '\n')
    temp.replace(META)

def run(argv, seconds):
    # Raw output stays in memory; error messages/SSH diagnostics are never exported.
    result = subprocess.run(argv, cwd=REPO, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=seconds)
    if result.returncode:
        raise RuntimeError('ChildReturnCode_' + str(result.returncode))
    return result.stdout

def fixture(action):
    remote = shlex.join(['sudo', 'python3', '-c', LINUX, action, TOKEN])
    output = run([sys.executable, 'scripts/windows/fixture_vm.py', 'ssh', remote], 35)
    return json.loads(output.strip())

def windows(script, seconds=70):
    output = run([sys.executable, 'scripts/windows/vm.py', 'ps', args.machine, script], seconds)
    lines = [x[len('V443_PARTIAL_JSON:'):] for x in output.splitlines()
             if x.startswith('V443_PARTIAL_JSON:')]
    if len(lines) != 1:
        raise RuntimeError('MissingSanitizedGuestJSON')
    return json.loads(lines[0])

def published(phase, seconds=70):
    # Concurrent Set-Content can briefly expose incomplete JSON; retry without logging it.
    return windows(r"$d='" + GUEST_REPORTS + r"';$f=Get-ChildItem -LiteralPath $d -Filter '*-" + phase + r".json' -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1;try{$v=if($f){Get-Content -LiteralPath $f.FullName -Raw|ConvertFrom-Json}else{$null};$o=@{path=$f.FullName;report=$v}}catch{$o=@{writing=$true}};'V443_PARTIAL_JSON:'+($o|ConvertTo-Json -Depth 14 -Compress)", seconds)

def launch(phase):
    existing = published(phase)
    previous = existing.get('path')
    arguments = f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{GUEST_SCRIPT}" -Phase {phase} -ExpectedBackendSha256 {args.backend}'
    value = windows(r"$p=Start-Process -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '" + arguments + r"' -WindowStyle Hidden -PassThru;'V443_PARTIAL_JSON:'+(@{pid=$p.Id;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress)")
    STATE[phase + 'Launch'] = value
    save()
    return previous

def poll(phase, previous, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            current = published(phase, min(70, max(1, deadline-time.monotonic())))
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            STATE.setdefault('pollErrors', []).append({'phase': phase, 'utc': utc(), 'type': type(exc).__name__})
            save()
            time.sleep(min(10, max(0, deadline-time.monotonic())))
            continue
        if current.get('path') != previous and current.get('report'):
            STATE[phase] = current
            # Published PS report is already allowlisted/sanitized; keep the full checks separately.
            (OUT / ('r8-partial-' + phase + '-' + STAMP + '.json')).write_text(json.dumps(current, indent=2) + '\n')
            save()
            if current['report'].get('completed'):
                return bool(current['report'].get('passed'))
        time.sleep(min(10, max(0, deadline-time.monotonic())))
    raise TimeoutError(phase + 'Deadline')

def interrupt(signum, _frame):
    STATE['interruptedSignal'] = signal.Signals(signum).name
    raise KeyboardInterrupt


def main():
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    attempted = False
    blocked_passed = False
    save()
    try:
        baseline = published('baseline')
        if not (baseline.get('report') or {}).get('completed') or not baseline['report'].get('passed'):
            raise RuntimeError('LatestBaselineNotPassed')
        STATE['baseline'] = baseline
        expected_machine = 'VAULT443-' + args.machine.upper()
        if baseline['report'].get('daemonSHA') != args.backend or (baseline['report'].get('identity') or {}).get('machine') != expected_machine:
            raise RuntimeError('BaselineCandidateOrMachineMismatch')
        preflight_script = (
            r"""$s=Get-CimInstance Win32_Service -Filter "Name='Vault443'";$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$s.ProcessId);'V443_PARTIAL_JSON:'+(@{machine=$env:COMPUTERNAME;state=$s.State;pid=[int]$s.ProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o');backend=(Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant();script=(Get-FileHash '"""
            + GUEST_SCRIPT
            + r"""').Hash.ToLowerInvariant()}|ConvertTo-Json -Compress)"""
        )
        preflight = windows(preflight_script)
        identity = baseline['report']['identity']
        if preflight['machine'] != expected_machine or preflight['state'] != 'Running' or preflight['backend'] != args.backend or preflight['script'] != SCRIPT_SHA or preflight['pid'] != identity['daemonPID'] or preflight['created'] != identity['daemonCreated']:
            raise RuntimeError('LiveCandidateScriptOrBaselineIdentityMismatch')
        STATE['preflight'] = preflight
        for phase in ('blocked', 'recovered'):
            old = published(phase)
            if old.get('report') and not old['report'].get('completed'):
                raise RuntimeError('AnotherPhaseStillRunning')
        attempted = True  # even a failed create may have durably written our journal
        STATE['fault'] = fixture('create')
        STATE['faultStartedUTC'] = utc()
        save()
        previous = launch('blocked')
        blocked_passed = poll('blocked', previous, 420)
        if not blocked_passed:
            raise RuntimeError('BlockedChecksFailed')
    except (Exception, KeyboardInterrupt) as exc:
        STATE['errors'].append({'utc': utc(), 'type': type(exc).__name__})
    finally:
        # A second stop request must not strand our DROP; every nested operation is bounded.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if attempted:
            try:
                STATE['cleanup'] = fixture('cleanup')
                STATE['faultRemovedUTC'] = utc()
            except Exception as exc:
                STATE['errors'].append({'utc': utc(), 'phase': 'cleanup', 'type': type(exc).__name__})
            save()
            if (STATE.get('cleanup') or {}).get('cleaned'):
                try:
                    previous = launch('recovered')
                    recovered_passed = poll('recovered', previous, 180)
                    STATE['passed'] = blocked_passed and recovered_passed and not STATE['errors']
                except Exception as exc:
                    STATE['errors'].append({'utc': utc(), 'phase': 'recovered', 'type': type(exc).__name__})
        STATE['returnCode'] = 0 if STATE['passed'] else 1
        STATE['completed'] = True
        STATE['finishedUTC'] = utc()
        save()
    print(json.dumps({'passed': STATE['passed'], 'metadata': str(META), 'cleanup': bool((STATE.get('cleanup') or {}).get('cleaned'))}))
    return 0 if STATE['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
