param([ValidateSet('compiler','core','gui','package')][string]$Stage = 'compiler')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$exchange = 'C:\Users\Public\Vault443Exchange'
$root = 'C:\Vault443Build'
$sdk = 'C:\Vault443SDK'
New-Item -ItemType Directory -Force $root,$sdk | Out-Null
Start-Transcript -Path "$root\$Stage.log" -Force | Out-Null
function Expand-SDK([string]$Archive, [string]$Directory) {
    $marker = Join-Path $Directory '.vault443-extracted'
    if (Test-Path $marker) { return }
    New-Item -ItemType Directory -Force $Directory | Out-Null
    Write-Output "Extracting $Archive"
    & "$env:SystemRoot\System32\tar.exe" -xf $Archive -C $Directory
    if ($LASTEXITCODE) { throw "SDK extraction failed: $Archive" }
    New-Item -ItemType File -Force $marker | Out-Null
}
try {
    if ((Get-TimeZone).Id -ne 'UTC') { Set-TimeZone -Id 'UTC' }
    if ($Stage -eq 'compiler') {
        $arguments = '--quiet --wait --norestart --noUpdateInstaller --installPath C:\Vault443BuildTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.26100 --add Microsoft.VisualStudio.Component.VC.CMake.Project --add Microsoft.VisualStudio.Component.VC.Redist.14.Latest'
        $process = Start-Process "$exchange\vs-buildtools.exe" -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -notin @(0,3010)) { throw "MSVC installation failed ($($process.ExitCode)); see %TEMP%\dd_* logs" }
        $process = Start-Process "$exchange\inno.exe" -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR=C:\Vault443Inno' -Wait -PassThru
        if ($process.ExitCode) { throw "Inno Setup installation failed ($($process.ExitCode))" }
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $installation = & $vswhere -products Microsoft.VisualStudio.Product.BuildTools -format json | ConvertFrom-Json
        if ($installation[0].installationVersion -ne '17.14.37827.9') { throw 'Unexpected MSVC 2022 build version' }
        $installation | ConvertTo-Json -Depth 10 | Set-Content "$root\msvc-installation.json"
    } else {
        Expand-SDK "$exchange\qt-sdk.zip" "$sdk\Qt"
        Expand-SDK "$exchange\qtbase-source.zip" "$sdk\qtbase"
        Expand-SDK "$exchange\python.zip" "$sdk\Python"
        # Import the native compiler environment into this process, without
        # changing machine/user PATH or using the guest's current shell profile.
        cmd.exe /s /c '"C:\Vault443BuildTools\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul && set' | ForEach-Object {
            if ($_ -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
        }
        if ($LASTEXITCODE) { throw 'MSVC environment failed' }
        $env:PATH = "C:\Vault443BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;C:\Vault443BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;$sdk\Qt\bin;$sdk\Python;$env:PATH"
        if ($Stage -eq 'core') {
            cmake -S "$sdk\qtbase" -B "$root\qtbase" -G Ninja -DCMAKE_BUILD_TYPE=Release -DQT_BUILD_TESTS=OFF -DQT_BUILD_EXAMPLES=OFF -DQT_FEATURE_icu=OFF
            if ($LASTEXITCODE) { throw 'QtBase configuration failed' }
            cmake --build "$root\qtbase" --target Core --parallel 4
            if ($LASTEXITCODE) { throw 'Patched QtCore build failed' }
            Copy-Item "$root\qtbase\bin\Qt6Core.dll" "$sdk\Qt\bin\Qt6Core.dll" -Force
            Copy-Item "$root\qtbase\lib\Qt6Core.lib" "$sdk\Qt\lib\Qt6Core.lib" -Force
            Get-FileHash "$sdk\Qt\bin\Qt6Core.dll" -Algorithm SHA256 | Format-List
        } elseif ($Stage -eq 'gui') {
            New-Item -ItemType Directory -Force "$root\source" | Out-Null
            & "$sdk\Python\python.exe" "$exchange\extract_sources.py" "$exchange\source.zip" "$root\source"
            if ($LASTEXITCODE) { throw 'Source extraction failed' }
            cmake -S "$root\source" -B "$root\gui" -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$sdk\Qt" -DVAULT443_BUILD_UI_TESTS=ON
            if ($LASTEXITCODE) { throw 'Vault443 UI configuration failed' }
            cmake --build "$root\gui" --parallel 4
            if ($LASTEXITCODE) { throw 'Vault443 UI build failed' }
            New-Item -ItemType Directory -Force "$root\stage" | Out-Null
            Copy-Item "$exchange\app\*" "$root\stage" -Force -Recurse
            Copy-Item "$root\gui\vault443.exe" "$root\stage" -Force
            windeployqt --release --no-translations --no-compiler-runtime --qmldir "$root\source\ui\qml" --dir "$root\stage" "$root\stage\vault443.exe"
            if ($LASTEXITCODE) { throw 'Qt deployment failed' }
            $crt = Get-ChildItem 'C:\Vault443BuildTools\VC\Redist\MSVC\*\x64\Microsoft.VC143.CRT' -Directory | Sort-Object FullName -Descending | Select-Object -First 1
            if (!$crt) { throw 'Pinned MSVC CRT directory is missing' }
            Copy-Item "$($crt.FullName)\*.dll" "$root\stage" -Force
            $installation = Get-Content "$root\msvc-installation.json" -Raw | ConvertFrom-Json | Select-Object -First 1
            $manifest = [ordered]@{
                msvc = [ordered]@{
                    product = $installation.productId
                    installationVersion = $installation.installationVersion
                    productDisplayVersion = $installation.catalog.productDisplayVersion
                    channel = $installation.channelId
                    toolsVersion = $env:VCToolsVersion
                }
                msvcRuntimeVersion = (Get-Item "$root\stage\vcruntime140.dll").VersionInfo.FileVersion
                innoVersion = (& C:\Vault443Inno\ISCC.exe --version)
                innoCompilerSha256 = (Get-FileHash C:\Vault443Inno\ISCC.exe -Algorithm SHA256).Hash.ToLowerInvariant()
                compiler = (Get-Item "$env:VCToolsInstallDir\bin\Hostx64\x64\cl.exe").VersionInfo.FileVersion
                windowsSdk = $env:WindowsSDKVersion
                cmake = (& cmake --version | Select-Object -First 1)
                ninja = (& ninja --version)
                qtVersion = '6.12.0'
                qtBasePatchSha256 = 'c27d27b86aaf2cdab0c18d513fbb94a432e98782eddfc5f856387e4be68be50b'
                qtCoreSha256 = (Get-FileHash "$root\stage\Qt6Core.dll" -Algorithm SHA256).Hash.ToLowerInvariant()
                sourceSha256 = (Get-FileHash "$exchange\source.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            $manifest | ConvertTo-Json -Depth 12 | Set-Content "$root\native-toolchain.json" -Encoding UTF8
        } elseif ($Stage -eq 'package') {
            # Preserve the already-built native UI/Qt payload; refresh only the
            # exact backend and matching notices before manifest validation.
            Copy-Item "$exchange\app\*" "$root\stage" -Force -Recurse
            Copy-Item "$exchange\licenses-stage\*" "$root\stage" -Force -Recurse
            # App-local x64 CRT DLLs are shipped directly. Qt's optional Burn
            # redistributable bootstrapper is x86 and is not an app dependency.
            Remove-Item "$root\stage\vc_redist.x64.exe" -Force -ErrorAction SilentlyContinue
            & "$sdk\Python\python.exe" "$exchange\extract_sources.py" "$exchange\source.zip" "$root\source"
            if ($LASTEXITCODE) { throw 'Source extraction failed' }
            & "$sdk\Python\python.exe" "$root\source\scripts\windows\package.py" compile --stage "$root\stage" --source "$exchange\source.zip" --toolchain "$root\native-toolchain.json" --output "$root\dist" --iscc C:\Vault443Inno\ISCC.exe
            if ($LASTEXITCODE) { throw 'Installer compilation failed' }
        }
    }
    'PASS' | Set-Content "$root\$Stage.result"
} catch {
    Write-Output $_.Exception.ToString()
    Write-Output $_.ScriptStackTrace
    'FAIL' | Set-Content "$root\$Stage.result"
    Stop-Transcript | Out-Null
    exit 1
}
Stop-Transcript | Out-Null
