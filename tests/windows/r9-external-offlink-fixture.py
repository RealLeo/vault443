#!/usr/bin/env python3
"""Run only INSIDE the marked root Linux fixture; create/inspect/cleanup exact NAT."""
import json,os,socket,stat,subprocess,sys,uuid
from pathlib import Path
act,token=sys.argv[1:]
if act not in ('create','inspect','cleanup') or str(uuid.UUID(token))!=token:raise RuntimeError('FixedActionAndTokenRequired')
if os.geteuid()!=0 or socket.gethostname()!='vault443-fixture':raise RuntimeError('NamedRootFixtureRequired')
m=Path('/etc/vault443-fixture-guest');a=m.lstat()
if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or m.read_text().strip()!='isolated Windows VPN acceptance fixture':raise RuntimeError('FixtureMarkerRequired')
if Path('/sys/class/net/fixture0/address').read_text().strip().lower()!='08:00:27:44:30:02':raise RuntimeError('FixtureMACChanged')
T='vault443_r9_offlink';J=Path('/run/vault443-r9-offlink.json');comment='Vault443R9Offlink:'+token
owner={'schema':1,'token':token,'table':T,'machine':'vault443-fixture'}
def cmd(v):return subprocess.run(v,check=True,capture_output=True,text=True,timeout=10).stdout
def listed():
 tables=json.loads(cmd(['nft','-j','list','tables']))['nftables']
 if not any(x.get('table',{}).get('family')=='ip' and x.get('table',{}).get('name')==T for x in tables):return None
 return [x for x in json.loads(cmd(['nft','-j','list','table','ip',T]))['nftables'] if 'metainfo' not in x]
def inspect(items):
 if items is None:return None
 if len(items)!=3:raise RuntimeError('ForeignObjectsRefuseCleanup')
 table=[x['table'] for x in items if 'table' in x];chains=[x['chain'] for x in items if 'chain' in x];rules=[x['rule'] for x in items if 'rule' in x]
 if len(table)!=1 or table[0].get('name')!=T or table[0].get('family')!='ip' or len(chains)!=1 or len(rules)!=1:raise RuntimeError('ForeignNATStructure')
 c=chains[0];r=rules[0]
 if c.get('table')!=T or c.get('family')!='ip' or c.get('name')!='prerouting' or c.get('type')!='nat' or c.get('hook')!='prerouting' or c.get('prio')!=-101 or c.get('policy')!='accept' or r.get('comment')!=comment or r.get('chain')!='prerouting':raise RuntimeError('ForeignNATIdentity')
 expected=[{'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'fixture0'}},{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'192.0.2.2'}},{'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':'93.184.215.14'}},{'match':{'op':'==','left':{'payload':{'protocol':'udp','field':'dport'}},'right':1194}}]
 expr=[x for x in r['expr'] if 'counter' not in x and x not in ({'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':17}},{'match':{'op':'==','left':{'meta':{'key':'l4proto'}},'right':'udp'}})]
 # nft versions emit an explicit family in the DNAT JSON on some releases.
 dnat=[x for x in expr if 'dnat' in x];base=[x for x in expr if 'dnat' not in x]
 if base!=expected or len(dnat)!=1 or dnat[0]['dnat'].get('addr')!='192.0.2.1' or dnat[0]['dnat'].get('port')!=1194 or any(k not in ('addr','port','family') for k in dnat[0]['dnat']):raise RuntimeError('ForeignNATExpression')
 counters=[x['counter'] for x in r['expr'] if 'counter' in x]
 if len(counters)!=1:raise RuntimeError('CounterMissing')
 return counters[0]
if act=='create':
 if J.exists() or J.is_symlink() or listed() is not None:raise RuntimeError('PreexistingOwnerOrTableRefused')
 ips=json.loads(cmd(['ip','-4','-j','address','show','dev','lo']))
 if not any(a.get('local')=='93.184.215.14' for i in ips for a in i['addr_info']):raise RuntimeError('ExistingFixtureOfflinkAliasRequired')
 config=Path('/fixture/openvpn/server.conf').read_text().splitlines()
 if config.count('local 192.0.2.1')!=1 or config.count('port 1194')!=1 or config.count('proto udp')!=1:raise RuntimeError('KnownLocalOpenVPNListenerRequired')
 fd=os.open(J,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(owner,f);f.flush();os.fsync(f.fileno())
 batch=f'add table ip {T}\nadd chain ip {T} prerouting {{ type nat hook prerouting priority -101; policy accept; }}\nadd rule ip {T} prerouting iifname "fixture0" ip saddr 192.0.2.2 ip daddr 93.184.215.14 udp dport 1194 counter dnat to 192.0.2.1:1194 comment "{comment}"\n'
 subprocess.run(['nft','-f','-'],input=batch,text=True,check=True,capture_output=True,timeout=10)
else:
 if not J.exists():
  if listed() is not None:raise RuntimeError('UnownedNATTableRefused')
  if act=='cleanup':print(json.dumps({'cleaned':True,'nothingCreated':True}));sys.exit(0)
  raise RuntimeError('OwnerJournalMissing')
 a=J.lstat()
 if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or stat.S_IMODE(a.st_mode)!=0o600 or json.loads(J.read_text())!=owner:raise RuntimeError('ForeignJournal')
counters=inspect(listed())
if act=='cleanup':
 if listed() is not None:cmd(['nft','delete','table','ip',T])
 if listed() is not None:raise RuntimeError('NATRemovalNotConfirmed')
 J.unlink()
print(json.dumps({'action':act,'token':token,'created':act=='create','cleaned':act=='cleanup','counters':counters}))
