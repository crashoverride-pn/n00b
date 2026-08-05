param(
    [string]$BuildDir = "build_msvc",
    [string]$BuildType = "debug",
    [string]$NccPath = "",
    [string]$LogPath = "",
    [string[]]$Target = @(),
    [switch]$SetupOnly,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$MesonArgs
)

$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
if ($Root -eq "") {
    $Root = (Get-Location).Path
}

if ($NccPath -eq "") {
    if ($env:NCC_PATH) {
        $NccPath = $env:NCC_PATH
    } else {
        $NeighborNcc = Join-Path $Root "..\ncc\build-msvc\ncc.exe"
        if (Test-Path $NeighborNcc) {
            $NccPath = (Resolve-Path $NeighborNcc).Path
        }
    }
}

if ($NccPath -eq "") {
    $NccCommand = Get-Command ncc.exe -ErrorAction SilentlyContinue
    if ($NccCommand) {
        $NccPath = $NccCommand.Source
    }
}

if ($NccPath -eq "" -or -not (Test-Path $NccPath)) {
    throw "ncc.exe not found. Set -NccPath or NCC_PATH, or build ..\ncc\build-msvc\ncc.exe."
}

$ResolvedLogPath = ""
if ($LogPath -ne "") {
    if ([System.IO.Path]::IsPathRooted($LogPath)) {
        $ResolvedLogPath = $LogPath
    } else {
        $ResolvedLogPath = Join-Path $Root $LogPath
    }

    $LogDir = Split-Path -Parent $ResolvedLogPath
    if ($LogDir -ne "" -and -not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir | Out-Null
    }

    Set-Content -Path $ResolvedLogPath -Value "build.ps1: log started $(Get-Date -Format o)" -Encoding utf8
}

function Write-BuildMessage {
    param([string]$Message)

    Write-Host $Message
    if ($script:ResolvedLogPath -ne "") {
        Add-Content -Path $script:ResolvedLogPath -Value $Message -Encoding utf8
    }
}

function Invoke-BuildNative {
    param(
        [string]$Command,
        [string[]]$Arguments
    )

    Write-BuildMessage ("build.ps1: running {0} {1}" -f $Command, ($Arguments -join " "))
    & $Command @Arguments 2>&1 | ForEach-Object {
        Write-Host $_
        Add-Content -Path $script:ResolvedLogPath -Value $_ -Encoding utf8
    }

    return $LASTEXITCODE
}

function Test-HasMesonOption {
    param(
        [string[]]$Arguments,
        [string]$OptionName
    )

    foreach ($Argument in $Arguments) {
        if ($Argument -match "^-D$([regex]::Escape($OptionName))=") {
            return $true
        }
    }

    return $false
}

$OriginalPythonPath = $env:PYTHONPATH
$OriginalPath = $env:Path

function Enable-WindowsPythonTempfileAclWorkaround {
    if ($env:OS -ne "Windows_NT") {
        return
    }

    $SiteDir = Join-Path $Root "scripts\windows-python-site"
    if (-not (Test-Path (Join-Path $SiteDir "sitecustomize.py"))) {
        return
    }

    if ($env:PYTHONPATH) {
        $env:PYTHONPATH = "$SiteDir;$env:PYTHONPATH"
    } else {
        $env:PYTHONPATH = $SiteDir
    }

    Write-BuildMessage "build.ps1: enabled Python tempfile ACL workaround for Meson"
}

if ($env:OS -eq "Windows_NT") {
    if (-not ("N00bBuildErrorMode" -as [type])) {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;

public static class N00bBuildErrorMode {
    [DllImport("kernel32.dll")]
    public static extern uint SetErrorMode(uint uMode);
}
"@
    }

    $NoPopupErrorMode = 0x0001 -bor 0x0002 -bor 0x0004 -bor 0x8000
    [void][N00bBuildErrorMode]::SetErrorMode($NoPopupErrorMode)
    Write-BuildMessage "build.ps1: disabled native Windows crash popups for child tools"
}

Enable-WindowsPythonTempfileAclWorkaround

if ($env:OS -eq "Windows_NT") {
    $Libgit2Lib = Join-Path $Root "..\libgit2\build-codex-win-clean\RelWithDebInfo\git2.lib"
    foreach ($Argument in $MesonArgs) {
        if ($Argument -match "^-Dlibgit2_lib=(.+)$") {
            $Libgit2Lib = $Matches[1]
        }
    }
    $Libgit2Dir = Split-Path -Parent $Libgit2Lib
    if (Test-Path (Join-Path $Libgit2Dir "git2.dll")) {
        $env:Path = "$Libgit2Dir;$env:Path"
        Write-BuildMessage "build.ps1: added libgit2 runtime directory to PATH"
    }
}

if ($ResolvedLogPath -ne "") {
    Write-BuildMessage "build.ps1: writing build log to $ResolvedLogPath"
}

$env:CC = (Resolve-Path $NccPath).Path
Write-BuildMessage "build.ps1: compiling n00b with ncc at $env:CC"

$ExitCode = 0
Push-Location $Root
try {
    $SetupArgs = @("setup")
    if (Test-Path (Join-Path $BuildDir "meson-private\coredata.dat")) {
        $SetupArgs += "--reconfigure"
    }
    $SetupArgs += @(
        $BuildDir,
        "-Dusing_build_script=true",
        "-Dskip_vcs_check=true",
        "--buildtype=$BuildType"
    )
    if ($env:OS -eq "Windows_NT" -and -not (Test-HasMesonOption $MesonArgs "b_vscrt")) {
        $SetupArgs += "-Db_vscrt=md"
    }
    $SetupArgs += $MesonArgs

    if ($ResolvedLogPath -ne "") {
        $ExitCode = Invoke-BuildNative "meson" $SetupArgs
    } else {
        & meson @SetupArgs
        $ExitCode = $LASTEXITCODE
    }
    if ($ExitCode -ne 0) {
        Write-BuildMessage "build.ps1: meson exited with code $ExitCode"
    }

    if ($ExitCode -eq 0 -and -not $SetupOnly) {
        $NinjaArgs = @("-C", $BuildDir)
        if ($env:N00B_JOBS) {
            $NinjaArgs += @("-j", $env:N00B_JOBS)
        }
        $NinjaArgs += $Target

        if ($ResolvedLogPath -ne "") {
            $ExitCode = Invoke-BuildNative "ninja" $NinjaArgs
        } else {
            & ninja @NinjaArgs
            $ExitCode = $LASTEXITCODE
        }
        if ($ExitCode -ne 0) {
            Write-BuildMessage "build.ps1: ninja exited with code $ExitCode"
        }
    }
} finally {
    Pop-Location
    if ($null -eq $OriginalPythonPath) {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    } else {
        $env:PYTHONPATH = $OriginalPythonPath
    }
    $env:Path = $OriginalPath
    if ($ResolvedLogPath -ne "") {
        Write-BuildMessage "build.ps1: log ended $(Get-Date -Format o)"
    }
}

if ($ExitCode -ne 0) {
    exit $ExitCode
}
