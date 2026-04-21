# Reporting — Report Generation & Output Parsing

The `reporting` module generates comprehensive markdown test reports and parses process output logs.

## Files

| File | Class | Purpose |
|------|-------|---------|
| `report_generator.py` | `ReportGenerator` | Builds the full markdown test report |
| `output_parser.py` | `OutputParser` | Parses `managedsoftwareupdate` and other process output |

## Report Structure

Reports are saved as:

```
install_audit_[AppName]_[Version]_[Timestamp].md
```

### Sections

| Section | Contents |
|---------|----------|
| System Information | Hardware, OS, security tool versions, XProtect config, VM warnings, Rosetta status |
| Package Analysis | Deprecated dependency detection, security issues in installer scripts |
| VirusTotal Malware Analysis | Multi-engine detection results, direct links to VT reports |
| ThreatLabs Binary Analysis | Mach-O threat levels, YARA matches, developer info |
| XProtect Monitoring | Version, scan config, real-time detection events |
| Catalog Information | Munki catalog validation, selected package details |
| Installation Results | Success/failure, process output, error analysis |
| System Changes | New login items (managed/non-managed), file system changes, system extensions |
| Security Events | Tool alerts, persistence changes, network activity, camera/mic access |
| Configuration Profiles | Generated profiles, validation warnings, manual review items |
| Code Signing Analysis | Signature verification, certificate chain, trust evaluation |
| Uninstallation Results | Clean removal, residual artifacts |
| Raw BTM Sections | Full `sfltool dumpbtm` output for technical analysis |

### Report Title

The markdown heading is configurable via `defaults.report_title` in `~/.install_audit.json`.
