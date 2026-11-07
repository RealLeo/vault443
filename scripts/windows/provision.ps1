param([ValidateSet('service','fixture-network','nat-network')][string]$Mode = 'service', [string]$Exchange = 'C:\Users\Public\Vault443Exchange')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = Join-Path $env:USERPROFILE 'Vault443Build'
New-Item -ItemType Directory -Force $work | Out-Null
Start-Transcript -Path (Join-Path $work "provision-$Mode.log") -Force | Out-Null
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'UAC administrator approval is required' }
    # QA-only on-demand tasks keep VM administration independent of guest VPN networking.
    # They are absent from product packages and clean installer acceptance snapshots.
    foreach ($taskMode in @('service','fixture-network','nat-network')) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\v.ps1 -Mode $taskMode"
        $principalTask = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName "Vault443-QA-$taskMode" -Action $action -Principal $principalTask -Force | Out-Null
    }
    foreach ($buildStage in @('compiler','core','gui','package')) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\native-build.ps1 -Stage $buildStage"
        $principalTask = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
        Register-ScheduledTask -TaskName "Vault443-QA-build-$buildStage" -Action $action -Principal $principalTask -Force | Out-Null
    }
    $app = 'C:\Program Files\Vault443'
    if ($Mode -eq 'service') {
        $existing = Get-Service Vault443 -ErrorAction SilentlyContinue
        if ($existing -and $existing.Status -ne 'Stopped') { Stop-Service Vault443; $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(25)) }
        New-Item -ItemType Directory -Force $app | Out-Null
        Copy-Item (Join-Path $Exchange 'app\*') $app -Force -Recurse
        & "$app\vault443d.exe" --version
        & "$app\vault443d.exe" --install-service
        if ($LASTEXITCODE) { throw 'Windows service installation failed' }
        try { (Get-Service Vault443).WaitForStatus('Running', [TimeSpan]::FromSeconds(20)) }
        catch {
            if (Test-Path 'C:\ProgramData\Vault443\service.log') { Get-Content 'C:\ProgramData\Vault443\service.log' -Tail 30 }
            Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager'} -MaxEvents 4 | Format-List Message
            throw
        }
        & "$app\vault443-access.exe" --grant-console
        if ($LASTEXITCODE) { throw 'Could not grant the active console user access' }
        Get-Service Vault443 | Format-List Name,Status
    } elseif ($Mode -eq 'fixture-network') {
        $adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Wintun|WireGuard|VPN'} | Select-Object -First 1
        if (!$adapter) { throw 'No fixture uplink adapter' }
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Disabled
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress 192.0.2.2 -PrefixLength 24 -DefaultGateway 192.0.2.1 | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses 192.0.2.1
        Import-Certificate -FilePath (Join-Path $Exchange 'fixture-ca.crt') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -RouterDiscovery Disabled
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 | Where-Object {$_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notlike 'fe80:*'} | Remove-NetIPAddress -Confirm:$false
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress 2001:db8:44::2 -PrefixLength 64 -DefaultGateway 2001:db8:44::1 | Out-Null
        Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex | Format-List
    } else {
        $adapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -notmatch 'Wintun|WireGuard|VPN'} | Select-Object -First 1
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq 'Manual'} | Remove-NetIPAddress -Confirm:$false
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object {$_.Protocol -eq 'NetMgmt'} | Remove-NetRoute -Confirm:$false
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Enabled
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 | Where-Object {$_.PrefixOrigin -eq 'Manual' -and $_.IPAddress -notlike 'fe80:*'} | Remove-NetIPAddress -Confirm:$false
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object {$_.Protocol -eq 'NetMgmt'} | Remove-NetRoute -Confirm:$false
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -RouterDiscovery Enabled
        ipconfig /renew
    }
    'PASS' | Set-Content (Join-Path $work "provision-$Mode.result")
} catch {
    Write-Output $_.Exception.ToString()
    Write-Output $_.ScriptStackTrace
    'FAIL' | Set-Content (Join-Path $work "provision-$Mode.result")
    Stop-Transcript | Out-Null
    exit 1
}
Stop-Transcript | Out-Null
