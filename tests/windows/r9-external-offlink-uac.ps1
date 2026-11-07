param([Parameter(Mandatory=$true)][Guid]$FixtureToken)
$ErrorActionPreference='Stop';$f='C:\Users\Public\Vault443Exchange\r9-external-offlink.ps1'
if((Get-FileHash $f).Hash.ToLowerInvariant()-ne'9ab04781135baa50ab1ab8fdd802d77b17cc2ea498e5e93c1395b40e652b6661'){throw 'Pinned offlink controller differs'}
$p=Start-Process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Verb RunAs -PassThru -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$f+'" -FixtureToken '+$FixtureToken.ToString('D'))
try{[void]$p.Handle;if(!$p.WaitForExit(360000)){throw 'Offlink controller deadline; process retained for inspection'};if($p.ExitCode){throw 'Offlink controller failed; inspect protected report'}}finally{$p.Dispose()}
