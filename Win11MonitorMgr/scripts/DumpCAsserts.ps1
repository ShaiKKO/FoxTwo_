param(
    [string]$SrcRoot,
    [string]$OutDir
)
$ErrorActionPreference = 'SilentlyContinue'
try {
    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    }
    $outFile = Join-Path $OutDir 'C_ASSERTS.txt'

    if (-not (Test-Path -LiteralPath $SrcRoot)) {
        "Source root not found: $SrcRoot" | Out-File -Encoding utf8 -FilePath $outFile
        exit 0
    }

    $items = Get-ChildItem -Path $SrcRoot -Include *.c,*.h -File -Recurse
    $matches = $items | Select-String -Pattern 'C_ASSERT\s*\(' -AllMatches

    if ($matches) {
        $matches |
            ForEach-Object { "{0}:{1}: {2}" -f $_.Path, $_.LineNumber, ($_.Line.Trim()) } |
            Out-File -Encoding utf8 -FilePath $outFile
    }
    else {
        "No C_ASSERT found." | Out-File -Encoding utf8 -FilePath $outFile
    }
}
catch {
    try {
        ("Error collecting C_ASSERTs: {0}" -f $_) | Out-File -Encoding utf8 -FilePath (Join-Path $OutDir 'C_ASSERTS.txt')
    } catch {}
}
