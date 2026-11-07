param([ValidateSet('begin','status','verify','disconnect')][string]$Phase = 'status')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$cli = 'C:\Program Files\Vault443\vault443-cli.exe'
function Invoke-Vault([string]$Method, [object[]]$Parameters = @()) {
    $json = ConvertTo-Json -InputObject $Parameters -Compress -Depth 12
    $reply = $json | & $cli $Method
    if ($LASTEXITCODE) { throw "$Method failed: $reply" }
    if ($reply) { return ($reply | ConvertFrom-Json) }
}
if ($Phase -eq 'begin') {
    $parameters = Get-Content C:\Users\Public\Vault443Exchange\main-import.json -Raw | ConvertFrom-Json
    $draft = Invoke-Vault PrepareImport $parameters
    if ($draft.errors.Count -or !$draft.profiles.Count) { throw 'The fixture profile was not accepted' }
    $imported = Invoke-Vault CommitImport @($draft.draftId, '{}')
    $snapshot = Invoke-Vault GetSnapshot
    $id = $snapshot.profiles[0].id
    Invoke-Vault RequestConnect @($id) | ConvertTo-Json -Depth 8
} elseif ($Phase -eq 'verify') {
    $snapshot = Invoke-Vault GetSnapshot
    if ($snapshot.runtime.state -ne 'connected') { throw "Not connected: $($snapshot.runtime | ConvertTo-Json -Compress)" }
    $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://93.184.215.14:8080/' -TimeoutSec 12
    if ($response.Content -notmatch 'vless-e2e-ok') { throw 'Fixture marker is missing' }
    $response.Content
    Invoke-Vault GetDiagnostics | ConvertTo-Json -Depth 12
} elseif ($Phase -eq 'disconnect') {
    Invoke-Vault RequestDisconnect | ConvertTo-Json -Depth 8
} else {
    Invoke-Vault GetSnapshot | ConvertTo-Json -Depth 12
}
