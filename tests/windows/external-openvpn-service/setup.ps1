# Test-only; run explicitly elevated inside a named project Windows VM.
param([switch]$FullTunnel, [switch]$Uninstall,
    [string]$ProfilePath = (Join-Path $env:LOCALAPPDATA 'Vault443\qa-ui-import\fixture-openvpn.ovpn'))
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this QA setup with explicit administrator approval.' }
if ($env:COMPUTERNAME -notin @('vault443-win10','vault443-win11')) { throw 'Only the named Windows acceptance VMs are allowed.' }
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Model -notmatch 'VirtualBox') { throw 'This fixture requires the private VirtualBox acceptance VM.' }
$qaMarker = 'C:\ProgramData\Vault443-QA\marker'
if (-not (Test-Path -LiteralPath $qaMarker) -or (Get-Content -LiteralPath $qaMarker -Raw).Trim() -ne 'Vault443 isolated Windows fixture') { throw 'The privileged QA bootstrap marker is missing.' }
$program = 'C:\Program Files\Vault443ExternalFixture'
$data = 'C:\ProgramData\Vault443ExternalFixture'
$image = Join-Path $program 'vault443-external-openvpn.exe'
if ($Uninstall) {
    if (Test-Path -LiteralPath $image) {
        & $image --uninstall
        if ($LASTEXITCODE) { throw 'Fixture service removal failed; files retained.' }
    }
    Write-Output 'Fixture service removed. Protected logs/config retained for inspection; remove its two dedicated directories explicitly after collecting evidence.'
    return
}
if (Get-Service -Name CorpExternalOpenVPNFixture -ErrorAction SilentlyContinue) { throw 'Uninstall the existing fixture service before changing its configuration.' }
$source = $ProfilePath
$sourceImage = 'C:\Users\Public\Vault443Exchange\vault443-external-openvpn.exe'
if ((Get-Item -LiteralPath $source).Length -gt 131072) { throw 'Fixture profile exceeds limits.' }
$raw = Get-Content -LiteralPath $source -Raw
$blocks = @{}
foreach ($kind in @('ca','cert','key')) {
    $matches = [regex]::Matches($raw, '(?ms)^<' + $kind + '>\s*\n(.*?)^</' + $kind + '>\s*$')
    if ($matches.Count -ne 1) { throw "Expected exactly one inline fixture $kind block." }
    $blocks[$kind] = $matches[0].Groups[1].Value.Trim()
    if ($blocks[$kind] -notmatch '^-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY)-----') { throw 'Unsupported fixture PEM block.' }
}
function Protect-Directory([string]$Path) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Fixture directories cannot be reparse points.' }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Protect-File([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Fixture files cannot be reparse points.' }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
Protect-Directory $program
Protect-Directory $data
Copy-Item -LiteralPath $sourceImage -Destination $image -Force
Protect-File $image
$utf8 = New-Object Text.UTF8Encoding($false)
$config = @'
client
proto udp
remote 192.0.2.1 1194
dev tun
dev-node corp-external
windows-driver wintun
disable-dco
nobind
persist-key
remote-cert-tls server
verify-x509-name vpn.e2e.invalid name
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
tun-mtu 1400
script-security 1
route-method ipapi
verb 3
'@ + "`n"
if ($FullTunnel) { $config += "redirect-gateway def1 ipv6`n" }
foreach ($kind in @('ca','cert','key')) { $config += "<$kind>`n" + $blocks[$kind] + "`n</$kind>`n" }
[IO.File]::WriteAllText((Join-Path $data 'client.ovpn'), $config, $utf8)
Protect-File (Join-Path $data 'client.ovpn')
& $image --install
if ($LASTEXITCODE) { throw 'Fixture service installation failed.' }
Write-Output 'Installed manual LocalSystem service CorpExternalOpenVPNFixture; it has NOT been started.'
Write-Output ('FullTunnel=' + [bool]$FullTunnel + '; adapter=corp-external; endpoint=192.0.2.1:1194/udp')
Write-Output 'Do not run the built-in work OpenVPN fixture concurrently: these profiles reuse the same temporary client certificate.'
