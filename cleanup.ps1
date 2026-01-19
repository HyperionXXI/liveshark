#Requires -Version 5.1
<#
.SYNOPSIS
    Clean LiveShark untracked artifacts safely (diffs, smoke outputs, LaTeX byproducts).
    Never touches tracked files. Never errors on git commands.
#>

$ErrorActionPreference = "Stop"
Set-Location "C:\GitHub\liveshark"

# Test if a path is tracked in git (safely, no error on untracked files)
function Test-IsTracked([string]$RelPath) {
    $out = & git ls-files -- "$RelPath" 2>$null
    return (-not [string]::IsNullOrWhiteSpace($out))
}

# Remove files only if they exist AND are untracked
function Remove-UntrackedFiles([string[]]$FullPaths, [string]$Label) {
    $cwd = (Get-Location).Path
    $targets = [System.Collections.Generic.List[string]]::new()

    foreach ($fp in $FullPaths) {
        # Skip if doesn't exist
        if (-not (Test-Path -LiteralPath $fp)) { continue }

        # Resolve to absolute path for safety check
        $resolved = (Resolve-Path -LiteralPath $fp).Path
        if (-not $resolved.StartsWith($cwd)) { continue }  # Safety: never outside repo

        # Convert to relative path
        $rel = $resolved.Substring($cwd.Length).TrimStart('\', '/')

        # Add to removal list only if untracked
        if (-not (Test-IsTracked $rel)) {
            $targets.Add($resolved)
        }
    }

    if ($targets.Count -eq 0) {
        Write-Host "OK: nothing to remove ($Label)"
        return
    }

    Write-Host "Will remove ($Label):"
    $targets | ForEach-Object { Write-Host "  $_" }

    foreach ($t in $targets) {
        Remove-Item -LiteralPath $t -Force
    }
    Write-Host "OK: removed ($Label)"
}

# ============================================================================
Write-Host "== CLEANUP START ==" -ForegroundColor Cyan
Write-Host ""

# Show state before
Write-Host "Before:" -ForegroundColor Gray
git status --short
Write-Host ""

# 0) Guard: remove literal file named "$null" if untracked
if (Test-Path -LiteralPath '$null') {
    if (-not (Test-IsTracked '$null')) {
        Write-Host "Removing stray file: `$null"
        Remove-Item -LiteralPath '$null' -Force
        Write-Host "✅ OK"
        Write-Host ""
    }
}

# A) Untracked *.diff files
$diffs = @(Get-ChildItem -Recurse -File -Filter "*.diff" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
Remove-UntrackedFiles $diffs "untracked *.diff"
Write-Host ""

# B) Untracked local smoke test outputs
Remove-UntrackedFiles @(
    (Join-Path (Get-Location) "test_report.json")
) "local smoke test outputs"
Write-Host ""

# C) LaTeX byproducts (spec/en and spec/fr)
$latexPatterns = @("*.aux", "*.log", "*.out", "*.toc", "*.lof", "*.lot", "*.fls", "*.fdb_latexmk", "*.synctex.gz", "*.bbl", "*.blg", "*.bcf", "*.run.xml")
$latexFiles = @()
foreach ($dir in @("spec\en", "spec\fr")) {
    if (Test-Path $dir) {
        foreach ($pattern in $latexPatterns) {
            $latexFiles += Get-ChildItem -Path $dir -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
        }
    }
}
Remove-UntrackedFiles $latexFiles "LaTeX byproducts (spec/en, spec/fr)"
Write-Host ""

# D) OPTIONAL: Untracked scratch documentation files in repo root
$scratchFiles = @(
    "NORMATIVE_FIXES_v0.2_SCHEMA.md",
    "SESSION_COMPLETE.md",
    "SPEC_UPDATE_SUMMARY.md",
    "v0.2_COMPLETE_STATUS.md",
    "v0.2_QUICK_REFERENCE.md"
)
$scratchPaths = @()
foreach ($name in $scratchFiles) {
    $path = Join-Path (Get-Location) $name
    if (Test-Path -LiteralPath $path) {
        $scratchPaths += $path
    }
}

if ($scratchPaths.Count -gt 0) {
    Write-Host "Optional: Remove scratch documentation?" -ForegroundColor Yellow
    Write-Host "Files:"
    $scratchPaths | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    Write-Host "To remove: Uncomment the line below and re-run"
    Write-Host "# Remove-UntrackedFiles `$scratchPaths 'untracked scratch *.md'"
    Write-Host ""
}

# ============================================================================
Write-Host "== CLEANUP DONE ==" -ForegroundColor Cyan
Write-Host ""

# Show state after
Write-Host "After:" -ForegroundColor Gray
git status --short
Write-Host ""

# Decision point: Cargo.lock
$status = git status --short
if ($status -match '^\s*M\s+Cargo\.lock') {
    Write-Host "Note: Cargo.lock is modified (tracked file)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Choose one:"
    Write-Host "  (A) Discard:  git restore Cargo.lock"
    Write-Host "  (B) Commit:   git add Cargo.lock && git commit -m 'chore: update Cargo.lock'"
    Write-Host ""
}
