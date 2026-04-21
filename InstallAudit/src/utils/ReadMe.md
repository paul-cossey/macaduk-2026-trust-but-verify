# Utils — Shared Utilities

The `utils` module provides shared helper functions for subprocess execution, file operations, and package analysis.

## Files

| File | Class / Purpose |
|------|----------------|
| `process_utils.py` | `ProcessUtils` — subprocess execution with output capture and error handling |
| `file_helpers.py` | `FileHelpers` — file and path utilities (temp files, directory management, etc.) |
| `binary_extractor.py` | Extracts Mach-O binaries from installed applications for ThreatLabs scanning |
| `package_analyzer.py` | Analyses PKG installer scripts for deprecated dependencies and security issues |
| `pkgcheck.sh` | Shell script for PKG file inspection (must be executable: `chmod +x`) |

## Package Security Analysis

The `package_analyzer` scans PKG files in the Munki cache (`/Library/Managed Installs/Cache`) for:

| Check | What It Flags |
|-------|--------------|
| Python 2 | Scripts using the deprecated Python 2 interpreter |
| Bash version | Scripts using old bash versions with known vulnerabilities |
| Perl | Scripts relying on the deprecated Perl interpreter |
| Ruby | Scripts using the deprecated Ruby interpreter |

Analysis results are included in the final test report, with critical issues highlighted.

### Scratch Directory

The `scratch/` subdirectory is used for temporary working files during package extraction and analysis.
