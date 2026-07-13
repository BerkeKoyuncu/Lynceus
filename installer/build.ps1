[CmdletBinding()]
param(
    [string]$Version,
    [switch]$InstallBuildTools,
    [switch]$PayloadOnly
)

$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) {
    throw "Project virtual environment was not found: $venvPython"
}

if (-not $Version) {
    $commitCount = (& git -C $repoRoot rev-list --count HEAD).Trim()
    $Version = "1.0.$commitCount"
}
if ($Version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
    throw "Version must be numeric, for example 1.2.3 or 1.2.3.4."
}

$iscc = $null
if (-not $PayloadOnly) {
    $isccCandidates = @(
        (Get-Command iscc.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    if (-not $isccCandidates -and $InstallBuildTools) {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $winget) {
            throw "winget is unavailable. Install Inno Setup 6 manually, then rerun the build."
        }
        & $winget.Source install --id JRSoftware.InnoSetup -e --accept-package-agreements --accept-source-agreements
        $isccCandidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        ) | Where-Object { Test-Path -LiteralPath $_ }
    }
    if (-not $isccCandidates) {
        throw "Inno Setup 6 was not found. Install it or rerun with -InstallBuildTools."
    }
    $iscc = @($isccCandidates)[0]
}

& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $PSScriptRoot "requirements-build.txt")

$buildRoot = Join-Path $PSScriptRoot "build"
$workRoot = Join-Path $buildRoot "work"
$distRoot = Join-Path $buildRoot "dist"
$outputRoot = Join-Path $PSScriptRoot "output"
foreach ($path in @($workRoot, $distRoot, $outputRoot)) {
    $resolvedParent = [System.IO.Path]::GetFullPath((Split-Path $path -Parent))
    if (-not $resolvedParent.StartsWith([System.IO.Path]::GetFullPath($PSScriptRoot))) {
        throw "Refusing to clean a build path outside installer/: $path"
    }
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $workRoot, $distRoot, $outputRoot | Out-Null

$commonPyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",
    "--paths", $repoRoot,
    "--distpath", $distRoot,
    "--workpath", $workRoot,
    "--specpath", $buildRoot
)

Push-Location $repoRoot
try {
    & $venvPython -m PyInstaller @commonPyInstallerArgs `
        --console `
        --name LynceusRuntime `
        --add-data "$(Join-Path $repoRoot 'templates');templates" `
        --add-data "$(Join-Path $repoRoot 'static');static" `
        --add-data "$(Join-Path $repoRoot 'migrations');migrations" `
        --collect-submodules routes `
        --collect-submodules services `
        --collect-all flask_migrate `
        --hidden-import logging.config `
        --exclude-module pytest `
        (Join-Path $PSScriptRoot "runtime.py")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller runtime build failed." }

    & $venvPython -m PyInstaller @commonPyInstallerArgs `
        --windowed `
        --name LynceusControl `
        (Join-Path $PSScriptRoot "control_panel.py")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller Control Panel build failed." }
}
finally {
    Pop-Location
}

if ($PayloadOnly) {
    Write-Host ""
    Write-Host "Payload build complete: $distRoot"
    return
}

$issFile = Join-Path $PSScriptRoot "lynceus.iss"
& $iscc "/DAppVersion=$Version" "/DPayloadRoot=$distRoot" "/DOutputRoot=$outputRoot" $issFile
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed."
}

$setup = Get-ChildItem -LiteralPath $outputRoot -Filter "Lynceus-Setup-*.exe" | Select-Object -First 1
if (-not $setup) {
    throw "Setup executable was not produced."
}
$hash = Get-FileHash -LiteralPath $setup.FullName -Algorithm SHA256
Write-Host ""
Write-Host "Build complete: $($setup.FullName)"
Write-Host "SHA256: $($hash.Hash)"
