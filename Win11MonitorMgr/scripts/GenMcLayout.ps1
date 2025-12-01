<#
 .SYNOPSIS
  Generate iop_mc_layout.h from a specific Windows kernel image and PDB via mc_layout_gen.

 .DESCRIPTION
  This script is invoked from the Win11MonitorMgr.vcxproj PreBuildEvent. It drives the
  mc_layout_gen.exe tool to emit a fresh iop_mc_layout.h (and a JSON sidecar) that matches
  the target ntoskrnl.exe / ntkrnlmp.pdb pair for the current Windows build.

  Default expectations:
    - mc_layout_gen.exe is built at:   <repoRoot>\tools\layout_gen\mc_layout_gen.exe
    - Kernel image is taken from:      %SystemRoot%\System32\ntoskrnl.exe
    - PDB is passed via -PdbPath (vcxproj uses <repoRoot>\symbols\ntkrnlmp.pdb)

  To support a different Windows build:
    1) Place the matching ntkrnlmp.pdb (or equivalent) under a path you control
       (for example, <repoRoot>\symbols\ntkrnlmp.pdb).
    2) Update the -PdbPath and -EraName arguments in the Win11MonitorMgr.vcxproj
       PreBuildEvent to point to that PDB and to a descriptive era label
       (e.g., WIN11_ERA_22000, WIN11_ERA_226XX).
    3) Rebuild the driver. The prebuild step will regenerate iop_mc_layout.h
       before compiling iop_mc.h, and C_ASSERTs will enforce layout consistency.
#>

param(
    [string]$McLayoutGenPath,
    [string]$NtImagePath,
    [string]$PdbPath,
    [string]$EraName,
    [string]$OutHeaderPath,
    [string]$OutJsonPath
)

$ErrorActionPreference = 'Stop'

try {
    $scriptDir   = $PSScriptRoot
    $projectRoot = Split-Path -LiteralPath $scriptDir -Parent
    $repoRoot    = Split-Path -LiteralPath $projectRoot -Parent

    if (-not $McLayoutGenPath) {
        $McLayoutGenPath = Join-Path -Path $repoRoot -ChildPath 'tools\layout_gen\mc_layout_gen.exe'
    }
    $McLayoutGenPath = [System.IO.Path]::GetFullPath($McLayoutGenPath)
    if (-not (Test-Path -LiteralPath $McLayoutGenPath)) {
        Write-Error ("mc_layout_gen executable not found: {0}" -f $McLayoutGenPath)
        exit 1
    }

    if (-not $NtImagePath) {
        $NtImagePath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\ntoskrnl.exe'
    }
    $NtImagePath = [System.IO.Path]::GetFullPath($NtImagePath)
    if (-not (Test-Path -LiteralPath $NtImagePath)) {
        Write-Error ("Kernel image not found: {0}" -f $NtImagePath)
        exit 1
    }

    if (-not $PdbPath) {
        Write-Error 'PdbPath is required (path to ntkrnlmp.pdb or equivalent).'
        exit 1
    }
    $PdbPath = [System.IO.Path]::GetFullPath($PdbPath)
    if (-not (Test-Path -LiteralPath $PdbPath)) {
        Write-Error ("PDB file not found: {0}" -f $PdbPath)
        exit 1
    }

    if (-not $EraName) {
        $EraName = 'UNKNOWN_ERA'
    }

    if (-not $OutHeaderPath) {
        $OutHeaderPath = Join-Path -Path $repoRoot -ChildPath 'iop_mc_layout.h'
    }
    $OutHeaderPath = [System.IO.Path]::GetFullPath($OutHeaderPath)
    $headerDir = Split-Path -LiteralPath $OutHeaderPath -Parent
    if (-not (Test-Path -LiteralPath $headerDir)) {
        New-Item -ItemType Directory -Force -Path $headerDir | Out-Null
    }

    if (-not $OutJsonPath) {
        $OutJsonPath = Join-Path -Path $repoRoot -ChildPath 'iop_mc_layout.json'
    }
    $OutJsonPath = [System.IO.Path]::GetFullPath($OutJsonPath)
    $jsonDir = Split-Path -LiteralPath $OutJsonPath -Parent
    if (-not (Test-Path -LiteralPath $jsonDir)) {
        New-Item -ItemType Directory -Force -Path $jsonDir | Out-Null
    }

    Write-Host ('[GenMcLayout] Using mc_layout_gen at: {0}' -f $McLayoutGenPath)
    Write-Host ('[GenMcLayout] Kernel image:             {0}' -f $NtImagePath)
    Write-Host ('[GenMcLayout] PDB:                     {0}' -f $PdbPath)
    Write-Host ('[GenMcLayout] Era:                     {0}' -f $EraName)
    Write-Host ('[GenMcLayout] Header output:           {0}' -f $OutHeaderPath)
    Write-Host ('[GenMcLayout] JSON output:             {0}' -f $OutJsonPath)

    $args = @(
        '--image', $NtImagePath,
        '--pdb', $PdbPath,
        '--out-header', $OutHeaderPath,
        '--out-json', $OutJsonPath,
        '--era', $EraName,
        '--verbose'
    )

    & $McLayoutGenPath @args
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Error ("mc_layout_gen failed with exit code {0}" -f $exitCode)
        exit $exitCode
    }

    Write-Host '[GenMcLayout] Layout generation completed successfully.'
}
catch {
    Write-Error ("[GenMcLayout] Unexpected error: {0}" -f $_)
    exit 1
}
