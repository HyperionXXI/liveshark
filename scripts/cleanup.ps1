<#
.SYNOPSIS
Clean up untracked files and artifacts from the repository.

.DESCRIPTION
Safely removes untracked development artifacts:
- Literal file named "$null" (if untracked)
- *.diff files (untracked)
- test_report.json (untracked)
- LaTeX byproducts under spec/en and spec/fr (untracked):
  *.aux, *.bbl, *.bcf, *.blg, *.fdb_latexmk, *.fls, *.log,
  *.out, *.run.xml, *.synctex.gz, *.toc, *.lof, *.lot

This script NEVER deletes tracked files (checked via 'git ls-files').
Files already in .gitignore may still be removed if they exist as untracked artifacts.

.PARAMETER DeleteScratchNotes
Optional. If specified, also removes untracked *.md files in root directory.
Default: $false (disabled for safety).

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1

.EXAMPLE
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1 -DeleteScratchNotes

.NOTES
Author: LiveShark Development
Date: 2026-01-20
#>

param(
    [switch]$DeleteScratchNotes = $false
)

$ErrorActionPreference = "Continue"  # Don't stop on individual file errors

Write-Host "LiveShark Repository Cleanup" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green
Write-Host ""

# Show before state
Write-Host "Before:" -ForegroundColor Cyan
git status --short
Write-Host ""

$filesToDelete = @()
$skippedFiles = @()

# Helper: Check if file is tracked in git
function Is-FileTracked($path) {
    $output = & git ls-files $path 2>$null
    return [bool]$output
}

# Helper: Check if file exists
function File-Exists($path) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        return $false
    }
    return Test-Path -LiteralPath $path -PathType Leaf
}

# 1. Literal file named "$null"
$nullFileName = "`$null"  # Literal string, not PowerShell variable
if (File-Exists $nullFileName) {
    if (Is-FileTracked $nullFileName) {
        $skippedFiles += "[SKIP] '$nullFileName' (TRACKED - keeping)"
    } else {
        $filesToDelete += $nullFileName
    }
}

# 2. *.diff files (untracked)
Get-ChildItem -Path "." -Filter "*.diff" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $path = $_.FullName -replace "^$(pwd)\\", ""
    if (Is-FileTracked $path) {
        $skippedFiles += "[SKIP] '$path' (TRACKED - keeping)"
    } else {
        $filesToDelete += $path
    }
}

# 3. test_report.json (untracked)
if (File-Exists "test_report.json") {
    if (Is-FileTracked "test_report.json") {
        $skippedFiles += "[SKIP] 'test_report.json' (TRACKED - keeping)"
    } else {
        $filesToDelete += "test_report.json"
    }
}

# 4. LaTeX byproducts under spec/en and spec/fr
$latexPatterns = @("*.aux", "*.bbl", "*.bcf", "*.blg", "*.fdb_latexmk", 
                   "*.fls", "*.log", "*.out", "*.run.xml", "*.synctex.gz", 
                   "*.toc", "*.lof", "*.lot")

foreach ($pattern in $latexPatterns) {
    Get-ChildItem -Path "spec/en" -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        $path = $_.FullName -replace "^$(pwd)\\", ""
        if (Is-FileTracked $path) {
            $skippedFiles += "[SKIP] '$path' (TRACKED - keeping)"
        } else {
            if ($filesToDelete -notcontains $path) {
                $filesToDelete += $path
            }
        }
    }
    
    Get-ChildItem -Path "spec/fr" -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        $path = $_.FullName -replace "^$(pwd)\\", ""
        if (Is-FileTracked $path) {
            $skippedFiles += "[SKIP] '$path' (TRACKED - keeping)"
        } else {
            if ($filesToDelete -notcontains $path) {
                $filesToDelete += $path
            }
        }
    }
}

# 5. Optional: Untracked *.md files in root (if -DeleteScratchNotes specified)
if ($DeleteScratchNotes) {
    Get-ChildItem -Path "." -Filter "*.md" -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false } | ForEach-Object {
        $path = $_.Name
        if (Is-FileTracked $path) {
            $skippedFiles += "[SKIP] '$path' (TRACKED - keeping)"
        } else {
            $filesToDelete += $path
        }
    }
}

# Display what will be deleted
if ($filesToDelete.Count -gt 0) {
    Write-Host "[DELETE] Found $($filesToDelete.Count) file(s) to remove:" -ForegroundColor Yellow
    $filesToDelete | ForEach-Object {
        Write-Host "   - $_"
    }
    Write-Host ""
} else {
    Write-Host "[OK] No files to delete." -ForegroundColor Green
}

if ($skippedFiles.Count -gt 0) {
    Write-Host "[SKIP] Skipped $($skippedFiles.Count) file(s) (tracked or not found):" -ForegroundColor Gray
    $skippedFiles | ForEach-Object {
        Write-Host "   $_"
    }
    Write-Host ""
}

# Delete files
$deleteCount = 0
$filesToDelete | ForEach-Object {
    $path = $_
    if (File-Exists $path) {
        try {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            Write-Host "   [OK] Deleted: $path" -ForegroundColor Green
            $deleteCount++
        } catch {
            Write-Host "   [ERROR] Failed to delete: $path" -ForegroundColor Red
            Write-Host "           $_"
        }
    }
}

Write-Host ""
if ($deleteCount -gt 0) {
    Write-Host "[OK] Deleted $deleteCount file(s)." -ForegroundColor Green
} else {
    Write-Host "[INFO] No changes made." -ForegroundColor Cyan
}

Write-Host ""

# Show after state
Write-Host "After:" -ForegroundColor Cyan
git status --short
Write-Host ""

$gitStatus = & git status --porcelain
if ([string]::IsNullOrWhiteSpace($gitStatus)) {
    Write-Host "[OK] Repository is clean." -ForegroundColor Green
} else {
    Write-Host "[WARN] Repository has pending changes (expected if .gitignore doesn't track them)." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
