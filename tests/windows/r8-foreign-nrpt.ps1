#Requires -Version 5.1
#Requires -RunAsAdministrator
# A foreign policy fixture: the app must preserve it through restart/uninstall.
# Only the exact journalled QA rule can be removed; never rewrite adapter DNS.
param([Parameter(Mandatory=$true)][ValidateSet('add','verify','remove')][string]$Mode)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$private='C:\ProgramData\Vault443-QA';$q='C:\Program Files\Vault443QA'
$path=Join-Path $private 'r8-foreign-nrpt.json'
$report=[ordered]@{mode=$Mode;startedUTC=[DateTime]::UtcNow.ToString('o');completed=$false;passed=$false;ruleGuid=$null;errorType=$null;errorLine=0}
function Protect([string]$File){
 $a=Get-Acl -LiteralPath $File
 if((Get-Item -LiteralPath $File -Force).Attributes-band[IO.FileAttributes]::ReparsePoint-or$a.GetOwner([Security.Principal.SecurityIdentifier]).Value-notin@('S-1-5-18','S-1-5-32-544')){throw 'Private QA ownership differs'}
 foreach($e in $a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($e.AccessControlType-eq'Allow'-and$e.IdentityReference.Value-notin@('S-1-5-18','S-1-5-32-544')-and([long]$e.FileSystemRights-band0xD00D017F)){throw 'Untrusted private QA access'}}
}
function Save-Journal($j){
 $tmp=$path+'.tmp';if(Test-Path $tmp){throw 'Prior QA journal temporary exists'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($j|ConvertTo-Json -Depth 6));$s=[IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
 if(Test-Path $path){[IO.File]::Replace($tmp,$path,[NullString]::Value)}else{[IO.File]::Move($tmp,$path)};Protect $path
}
function Read-Journal([string]$File){
 Protect $File;$j=Get-Content -LiteralPath $File -Raw|ConvertFrom-Json
 if($j.schemaVersion-ne1-or$j.machine-ne$env:COMPUTERNAME-or$j.controllerSID-ne$id.User.Value-or$j.phase-notin@('intent','active','removing')-or$j.before-isnot[Array]){throw 'Foreign QA journal schema/owner differs'}
 $prefix='Vault443 foreign NRPT QA ';$token=[Guid]::Empty
 if(!$j.display.StartsWith($prefix,[StringComparison]::Ordinal)-or![Guid]::TryParse($j.display.Substring($prefix.Length),[ref]$token)-or$j.display-cne($prefix+$token.ToString('D'))-or$j.comment-cne('Isolated foreign policy fixture '+$token.ToString('D'))){throw 'Foreign QA intent token differs'}
 $guid=[Guid]::Empty
 if($j.ruleGuid){if(![Guid]::TryParse([string]$j.ruleGuid,[ref]$guid)){throw 'Invalid foreign QA rule GUID'}}elseif($j.phase-ne'intent'){throw 'Foreign QA rule GUID missing'}
 return $j
}
function Recover-Journal {
 $tmp=$path+'.tmp';if(!(Test-Path $tmp)){return}
 Protect $tmp
 $committed=$null;if(Test-Path $path){$committed=Read-Journal $path}
 $partial=$false
 try{$pendingJSON=Get-Content -LiteralPath $tmp -Raw|ConvertFrom-Json -ErrorAction Stop;if(!$pendingJSON){$partial=$true}}catch{$partial=$true}
 if($partial){
  # No NRPT operation can precede this temporary's atomic commit. The prior
  # validated journal, if present, remains authoritative after a partial write.
  Remove-Item -LiteralPath $tmp;return
 }
 $pending=Read-Journal $tmp
 if($committed){
  if($pending.display-cne$committed.display-or$pending.comment-cne$committed.comment-or($committed.ruleGuid-and$pending.ruleGuid-ine$committed.ruleGuid)-or(ConvertTo-Json -InputObject @($pending.before) -Depth 6 -Compress)-cne(ConvertTo-Json -InputObject @($committed.before) -Depth 6 -Compress)){throw 'Journal temporary belongs to another intent'}
  # A mutation follows Save-Journal only after atomic replace succeeds.
  # The committed record remains authoritative; intent recovery finds an Add.
  Remove-Item -LiteralPath $tmp
 }else{
  if($pending.phase-ne'intent'-or$pending.ruleGuid){throw 'Uncommitted journal is not an initial intent'}
  [IO.File]::Move($tmp,$path);Protect $path
 }
}
function App-Rule {
 $p='C:\ProgramData\Vault443\windows-dns.json';if(!(Test-Path $p)){return ''}
 $d=Get-Content $p -Raw|ConvertFrom-Json
 if(!$d.nrpt-or!$d.nrpt.ruleGuid){return ''}
 return [string]$d.nrpt.ruleGuid
}
function Projection($rules){
 return @($rules|Sort-Object Name|ForEach-Object {[ordered]@{name=[string]$_.Name;namespace=@($_.Namespace|Sort-Object);servers=@((@($_.NameServers)-join ';')-split '[,;\s]+'|Where-Object{$_}|Sort-Object);display=[string]$_.DisplayName;comment=[string]$_.Comment;dnssec=[bool]$_.DnsSecValidationRequired}})
}
function Same-Rule($rule,$j){
 if([string]$rule.Name-ine[string]$j.ruleGuid-or@($rule.Namespace).Count-ne1-or$rule.Namespace[0]-ne'.corp.openvpn.test'-or(@($rule.NameServers)-join ';')-ne'192.0.2.1'-or$rule.DisplayName-cne$j.display-or$rule.Comment-cne$j.comment-or$rule.DnsSecValidationRequired){throw 'Exact foreign QA rule identity changed'}
}
try {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$m=Get-CimInstance Win32_ComputerSystem
 if($env:COMPUTERNAME-notin@('VAULT443-WIN10','VAULT443-WIN11')-or$m.Model-ne'VirtualBox'-or!$m.UserName-or([Security.Principal.NTAccount]::new($m.UserName)).Translate([Security.Principal.SecurityIdentifier]).Value-ne$id.User.Value){throw 'Same active console UAC controller required'}
 Protect $private;Protect (Join-Path $private 'qa-inputs.json');Protect (Join-Path $private 'marker')
 if([IO.File]::ReadAllText((Join-Path $private 'marker')).Trim()-ne'Vault443 isolated Windows fixture'){throw 'QA marker differs'}
 $inputs=Get-Content (Join-Path $private 'qa-inputs.json') -Raw|ConvertFrom-Json
 if($inputs.machine-ne$env:COMPUTERNAME-or$inputs.controllerSID-ne$id.User.Value){throw 'Bound QA controller differs'}
 Recover-Journal
 if($Mode-eq'add'){
  if(Test-Path $path){throw 'Existing foreign QA journal requires verify/remove first'}
  if((Get-FileHash 'C:\Program Files\Vault443\vault443d.exe').Hash.ToLowerInvariant()-ne'4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50'){throw 'R8 required'}
  $token=[Guid]::NewGuid().ToString('D');$app=App-Rule
  $j=[ordered]@{schemaVersion=1;machine=$env:COMPUTERNAME;controllerSID=$id.User.Value;phase='intent';ruleGuid='';display=('Vault443 foreign NRPT QA '+$token);comment=('Isolated foreign policy fixture '+$token);before=@(Projection @(Get-DnsClientNrptRule|Where-Object Name -ine $app))}
  Save-Journal $j
  $rule=Add-DnsClientNrptRule -Namespace '.corp.openvpn.test' -NameServers '192.0.2.1' -DisplayName $j.display -Comment $j.comment -PassThru -Confirm:$false
  $j.ruleGuid=[string]$rule.Name;$j.phase='active';Save-Journal $j
 }else{
  $j=Read-Journal $path
  if(!$j.ruleGuid){
   $r=@(Get-DnsClientNrptRule|Where-Object {$_.DisplayName-ceq$j.display-and$_.Comment-ceq$j.comment})
   if($r.Count-eq0-and$Mode-eq'remove'-and$j.phase-eq'intent'){
    $app=App-Rule;$current=@(Projection @(Get-DnsClientNrptRule|Where-Object Name -ine $app))
    if((ConvertTo-Json -InputObject $current -Depth 6 -Compress)-cne(ConvertTo-Json -InputObject @($j.before) -Depth 6 -Compress)){throw 'Interrupted intent baseline differs'}
    Remove-Item -LiteralPath $path;$report.passed=$true;$report['noRuleWasCreated']=$true
   }elseif($r.Count-ne1){throw 'Interrupted Add has no unique exact identity'}else{$j.ruleGuid=[string]$r[0].Name}
  }
 }
 if(!$report.passed){
 $matches=@(Get-DnsClientNrptRule|Where-Object Name -ieq $j.ruleGuid)
 if($matches.Count-eq1){Same-Rule $matches[0] $j}elseif(!($Mode-eq'remove'-and$j.phase-eq'removing'-and$matches.Count-eq0)){throw 'Foreign QA rule missing'}
 $report.ruleGuid=[string]$j.ruleGuid
 if($Mode-eq'remove'){
  $j.phase='removing';Save-Journal $j
  if($matches.Count){Remove-DnsClientNrptRule -Name $j.ruleGuid -Force -Confirm:$false}
  if(@(Get-DnsClientNrptRule|Where-Object Name -ieq $j.ruleGuid).Count){throw 'Exact QA removal incomplete'}
  $app=App-Rule;$after=@(Projection @(Get-DnsClientNrptRule|Where-Object Name -ine $app))
  if((ConvertTo-Json -InputObject $after -Depth 6 -Compress)-ne(ConvertTo-Json -InputObject @($j.before) -Depth 6 -Compress)){throw 'Unrelated policy changed; retain journal for inspection'}
  Remove-Item -LiteralPath $path
 }
 $report.passed=$true
 }
}catch{$report.errorType=$_.Exception.GetType().FullName;$report.errorLine=$_.InvocationInfo.ScriptLineNumber}
finally{$report.completed=$true;$report.finishedUTC=[DateTime]::UtcNow.ToString('o');$report|ConvertTo-Json -Depth 5|Set-Content (Join-Path $q ('reports\r8-foreign-nrpt-'+$Mode+'.json')) -Encoding UTF8}
$report|ConvertTo-Json -Depth 5
if(!$report.passed){exit 1}
