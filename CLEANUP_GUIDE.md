# Repository Cleanup Guide

## Quick Start

```powershell
# Standard cleanup (removes untracked development artifacts)
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1

# With optional scratch notes removal
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1 -DeleteScratchNotes
```

## What Gets Cleaned

### Standard Cleanup
- **Literal `$null` file** - Accidentally created file named `$null` (if untracked)
- **Diff files** - `*.diff` (untracked)
- **Test reports** - `test_report.json` (untracked)
- **LaTeX byproducts** - Under `spec/en/` and `spec/fr/`:
  - `*.aux`, `*.bbl`, `*.bcf`, `*.blg`, `*.fdb_latexmk`, `*.fls`
  - `*.log`, `*.out`, `*.run.xml`, `*.synctex.gz`, `*.toc`, `*.lof`, `*.lot`

### With `-DeleteScratchNotes`
- **Markdown files in root** - `*.md` files (untracked only, tracked files are protected)

## Safety Guarantees

✅ **Never deletes tracked files** - Verified against `git ls-files` before deletion
✅ **Shows before/after state** - `git status --short` before and after
✅ **Resilient to missing files** - No errors if artifacts don't exist
✅ **Reversible** - Use `git restore` if anything is accidentally deleted (though tracked files are protected)

## Examples

### Scenario 1: Clean after failed test
```powershell
# After running tests that generated test_report.json
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1
# → Removes test_report.json if untracked
```

### Scenario 2: Clean LaTeX builds before commit
```powershell
# After building PDF from TeX sources
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1
# → Removes *.aux, *.log, *.out, etc. from spec/ folders
```

### Scenario 3: Full clean including documentation scratch
```powershell
# Before major refactor
powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1 -DeleteScratchNotes
# → Removes untracked *.md files from root (e.g., temporary notes)
# → ✅ Protected: README.md, NOTICE, etc. (tracked files stay)
```

## Understanding the Output

```
LiveShark Repository Cleanup
============================

Before:
<git status before>

[DELETE] Found N file(s) to remove:
   - path/to/file1
   - path/to/file2

[OK] Deleted N file(s).

After:
<git status after>

[OK] Repository is clean.
```

- `[DELETE]` - Files that will be removed (untracked only)
- `[SKIP]` - Files protected because they are tracked
- `[OK]` - Operation completed successfully
- `[WARN]` - Pending changes detected (may be normal if other untracked files exist)

## Integration with .gitignore

The script respects the patterns already in [.gitignore](.gitignore). Adding patterns there means:

1. Files matching those patterns are ignored by git
2. If they exist untracked, cleanup.ps1 will remove them
3. New files matching those patterns won't be accidentally added to git

Current patterns handled:
```
*.diff
test_report.json
spec/**/*.aux
spec/**/*.log
... (see .gitignore for full list)
```

## Troubleshooting

### "Failed to delete: <file>"
- The file might have been locked by another process
- Check if a program is using the file (e.g., LaTeX editor, text editor)
- Close the program and run cleanup again

### "Repository is clean" but files still exist
- Files are probably in `.gitignore` but the cleanup patterns don't match
- Add new patterns to the script or to `.gitignore` as needed
- Patterns in the script must exactly match filenames/extensions

### "TRACKED" message for a file I want to delete
- The file is version-controlled (`git ls-files` shows it)
- Use `git rm` to untrack it first:
  ```powershell
  git rm <filename>
  git commit -m "Remove <filename>"
  ```
- Then run cleanup again

## For Contributors

When adding new untracked artifacts to the cleanup process:

1. **Update `scripts/cleanup.ps1`**:
   - Add a new pattern or file check section
   - Use `Is-FileTracked()` to verify git status
   - Add to `$filesToDelete` array if safe

2. **Update `.gitignore`**:
   - Add the pattern (e.g., `*.myext`) so files are ignored by git
   - This ensures they won't accidentally be committed

3. **Test**:
   ```powershell
   # Create a test file
   "test" | Out-File test_artifact.myext
   # Run cleanup
   powershell -ExecutionPolicy Bypass -File scripts/cleanup.ps1
   # Verify it was deleted
   Test-Path test_artifact.myext  # Should be False
   ```

## References

- [scripts/cleanup.ps1](scripts/cleanup.ps1) - Full script with inline documentation
- [.gitignore](.gitignore) - Patterns for ignored files
