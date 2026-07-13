[CmdletBinding()]
param(
    [string]$Version,
    [switch]$PayloadOnly
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic

# Define the Show-Error PowerShell operation.
function Show-Error([string]$Message) {
    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        "Lynceus Setup Builder",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

# Run this PowerShell operation with structured error handling.
try {
    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    $buildScript = Join-Path $PSScriptRoot "build.ps1"

    # Handle the branch where the PowerShell condition evaluates to true.
    if (-not $Version) {
        $commitCount = (& git -C $repoRoot rev-list --count HEAD).Trim()
        # Handle the branch where the PowerShell condition evaluates to true.
        if (-not $commitCount) { $commitCount = "0" }
        $suggestedVersion = "1.0.$commitCount"
        $Version = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Setup version (numeric format):",
            "Lynceus Setup Builder",
            $suggestedVersion
        ).Trim()
        # Handle the branch where the PowerShell condition evaluates to true.
        if (-not $Version) {
            throw "Build cancelled: no version was entered."
        }
    }

    # Handle the branch where the PowerShell condition evaluates to true.
    if ($PayloadOnly) {
        & $buildScript -Version $Version -PayloadOnly
        # Handle the branch where the PowerShell condition evaluates to true.
        if ($LASTEXITCODE -ne 0) { throw "Payload build failed." }
        [System.Windows.Forms.MessageBox]::Show(
            "Python/runtime payload build completed successfully.",
            "Lynceus Setup Builder",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        exit 0
    }

    & $buildScript `
        -Version $Version `
        -InstallBuildTools
    # Handle the branch where the PowerShell condition evaluates to true.
    if ($LASTEXITCODE -ne 0) {
        throw "Setup build failed. Review the PowerShell output for details."
    }

    $outputDir = Join-Path $PSScriptRoot "output"
    $setup = Get-ChildItem -LiteralPath $outputDir -Filter "Lynceus-Setup-$Version-x64.exe" |
        Select-Object -First 1
    # Handle the branch where the PowerShell condition evaluates to true.
    if (-not $setup) {
        throw "Build finished but the setup executable could not be found in $outputDir."
    }

    [System.Windows.Forms.MessageBox]::Show(
        "Setup created successfully:`n`n$($setup.FullName)",
        "Lynceus Setup Builder",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    Start-Process explorer.exe -ArgumentList "/select,`"$($setup.FullName)`""
    exit 0
}
# Handle errors raised by the preceding PowerShell operation.
catch {
    Show-Error $_.Exception.Message
    Write-Error $_.Exception.Message
    exit 1
}
