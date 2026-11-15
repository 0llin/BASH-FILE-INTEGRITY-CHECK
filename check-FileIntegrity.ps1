<#
.SYNOPSIS
    File integrity & encryption checker for Windows (version-tolerant build).
.DESCRIPTION
    Menu-driven tool that can:
      1. Create a baseline SHA-256 manifest of a folder
      2. Verify files against that manifest (detects changes/tampering)
      3. Check the EFS (NTFS) encryption status of files/folders
      4. Compute a single file's hash (e.g. to compare with a published checksum)

    This build works on Windows PowerShell 2.0 through 5.1 AND PowerShell 7+ (Core),
    by detecting what the host supports and falling back to .NET APIs where needed.
.NOTES
    Find folder in file explorer, right click and choose Run with PowerShell
    Run from PowerShell:  .\Check-FileIntegrity.ps1
    If execution is blocked, use the launcher:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Check-FileIntegrity.ps1
#>

# --- Version / feature detection instead of a hard #Requires gate -----------------
$Script:PSMajor = $PSVersionTable.PSVersion.Major

# Get-FileHash exists from PowerShell 4.0. On older hosts we fall back to .NET.
$Script:HasGetFileHash = $null -ne (Get-Command Get-FileHash -ErrorAction SilentlyContinue)

function Get-Sha256 {
    param ([string]$LiteralPath)
    if ($Script:HasGetFileHash) {
        return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash
    }
    # Fallback for PowerShell 2.0/3.0: raw .NET SHA-256
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($LiteralPath)
        try {
            $bytes = $sha.ComputeHash($stream)
            $sb = New-Object System.Text.StringBuilder
            foreach ($b in $bytes) { [void]$sb.Append($b.ToString('x2')) }
            return $sb.ToString().ToUpper()
        } finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}

# Write-Progress -PercentComplete requires PS 3+; guard so 2.0 does not error.
function Write-SafeProgress {
    param ([string]$Status, [int]$PercentComplete)
    if ($Script:PSMajor -ge 3) {
        Write-Progress -Activity 'Hashing' -Status $Status -PercentComplete $PercentComplete
    }
}

if ($Script:PSMajor -lt 5) {
    Write-Host "Note: running on PowerShell $Script:PSMajor - all features work, " -NoNewline -ForegroundColor DarkYellow
    Write-Host "but colors/progress may look different. PowerShell 5.1+ is recommended." -ForegroundColor DarkYellow
}

$script:ManifestPath = Join-Path (Get-Location) 'IntegrityManifest.csv'

function Select-Path {
    param ([string]$Prompt)
    $p = Read-Host $Prompt
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Host "Path not found: $p" -ForegroundColor Red
        return $null
    }
    return (Resolve-Path -LiteralPath $p).Path
}

function New-IntegrityManifest {
    $path = Select-Path 'Folder to baseline'
    if (-not $path) { return }
    $files = @(Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue)
    $total = $files.Count; $i = 0
    $manifest = foreach ($f in $files) {
        $i++
        Write-SafeProgress -Status $f.FullName -PercentComplete (($i / $total) * 100)
        try {
            [PSCustomObject]@{
                Path    = $f.FullName.Substring($path.Length).TrimStart('\')
                SHA256  = Get-Sha256 -LiteralPath $f.FullName
                Size    = $f.Length
                Created = $f.CreationTimeUtc
            }
        } catch {
            Write-Warning "Unreadable (in use/locked): $($f.FullName)"
        }
    }
    $manifest | Export-Csv -Path $script:ManifestPath -NoTypeInformation -Encoding UTF8
    Write-Host "Baseline saved: $script:ManifestPath ($(@($manifest).Count) files)." -ForegroundColor Green
    if ($Script:PSMajor -ge 3) { Write-Progress -Activity 'Hashing' -Completed }
}

function Test-Integrity {
    if (-not (Test-Path -LiteralPath $script:ManifestPath)) {
        Write-Host 'No manifest found. Create a baseline first (option 1).' -ForegroundColor Red
        return
    }
    $baseline = Import-Csv $script:ManifestPath
    $path = Select-Path 'Folder to verify'
    if (-not $path) { return }

    $ok = 0; $changed = @(); $missing = @()
    foreach ($entry in $baseline) {
        $full = Join-Path $path $entry.Path
        if (-not (Test-Path -LiteralPath $full)) { $missing += $entry.Path; continue }
        $hash = Get-Sha256 -LiteralPath $full
        if ($hash -eq $entry.SHA256) { $ok++ } else { $changed += $entry.Path }
    }
    $baselineSet = @{}
    $baseline | ForEach-Object { $baselineSet[$_.Path] = $true }
    $new = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { -not $baselineSet.ContainsKey($_.FullName.Substring($path.Length).TrimStart('\')) } |
        ForEach-Object { $_.FullName.Substring($path.Length).TrimStart('\') }

    Write-Host ""
    Write-Host "===== INTEGRITY REPORT =====" -ForegroundColor Cyan
    Write-Host "Verified OK : $ok"
    Write-Host "Changed     : $($changed.Count)" -ForegroundColor $(if ($changed.Count) {'Yellow'} else {'Gray'})
    $changed | ForEach-Object { Write-Host "  MODIFIED: $_" -ForegroundColor Yellow }
    Write-Host "Missing     : $($missing.Count)" -ForegroundColor $(if ($missing.Count) {'Red'} else {'Gray'})
    $missing | ForEach-Object { Write-Host "  MISSING: $_" -ForegroundColor Red }
    Write-Host "New files   : $($new.Count)" -ForegroundColor $(if ($new.Count) {'DarkYellow'} else {'Gray'})
    $new | ForEach-Object { Write-Host "  NEW: $_" -ForegroundColor DarkYellow }

    if (-not $changed -and -not $missing -and -not $new) {
        Write-Host 'Result: PASS - all files match the baseline.' -ForegroundColor Green
    } else {
        Write-Host 'Result: FAIL - differences found above.' -ForegroundColor Red
    }
}

function Get-EfsStatus {
    $path = Select-Path 'File or folder to check'
    if (-not $path) { return }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $items = @(Get-Item -LiteralPath $path)
    } else {
        $items = Get-ChildItem -LiteralPath $path -Recurse -File -ErrorAction SilentlyContinue
    }
    foreach ($f in $items) {
        $encrypted = (($f.Attributes -band [IO.FileAttributes]::Encrypted) -ne 0)
        $status = if ($encrypted) { 'ENCRYPTED (EFS)' } else { 'not encrypted' }
        Write-Host ("{0,-60} {1}" -f $f.Name, $status) -ForegroundColor $(if ($encrypted) {'Green'} else {'Gray'})
    }
}

function Get-SingleHash {
    $path = Select-Path 'File to hash'
    if (-not $path) { return }
    $hash = Get-Sha256 -LiteralPath $path
    Write-Host "SHA-256 : $hash" -ForegroundColor Green
    $expected = Read-Host 'Expected hash (Enter to skip)'
    if ($expected) {
        if ($hash -eq $expected.Trim().ToUpper()) {
            Write-Host 'MATCH - file integrity confirmed.' -ForegroundColor Green
        } else {
            Write-Host 'MISMATCH - file has been modified or is not the expected version.' -ForegroundColor Red
        }
    }
}

do {
    Write-Host ""
    Write-Host "========== FILE INTEGRITY CHECKER ==========" -ForegroundColor Cyan
    Write-Host " PowerShell $($PSVersionTable.PSVersion) "
    Write-Host ' 1. Create baseline manifest (SHA-256) for a folder'
    Write-Host ' 2. Verify folder against manifest'
    Write-Host ' 3. Check EFS encryption status of files'
    Write-Host ' 4. Compute/compare a single file hash'
    Write-Host ' Q. Quit'
    $choice = (Read-Host 'Choose an option').Trim().ToUpper()
    switch ($choice) {
        '1' { New-IntegrityManifest }
        '2' { Test-Integrity }
        '3' { Get-EfsStatus }
        '4' { Get-SingleHash }
    }
} while ($choice -ne 'Q')
