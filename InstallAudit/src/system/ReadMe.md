# System — State Checks & Comparisons

The `system` module captures system state before and after installation and compares the snapshots to identify changes.

## Files

| File | Class | Purpose |
|------|-------|---------|
| `checks.py` | `SystemChecker` | Gathers system information — hardware, OS, security tool versions, XProtect config |
| `comparisons.py` | `SystemComparator` | Compares pre/post BTM snapshots, login items, file system changes, system extensions |
| `notifications.py` | `NotificationChecker` | Analyses notification database changes |

## BTM (Background Task Management) Analysis

The `SystemComparator` parses `sfltool dumpbtm` output to detect new login items:

### Login Item Categories

| Category | Description | Profile RuleType |
|----------|-------------|-----------------|
| Managed | Traditional system-managed login items | `BundleIdentifier` |
| Non-managed | Application-specific login items | `BundleIdentifier` |
| LaunchAgents / LaunchDaemons | System-level persistence | `Label` |

### Detection Details

Each detected item includes:
- Full application path and metadata
- BTM type and enabled/disabled status
- Bundle ID, version, and code signing info
- Raw BTM section for technical analysis

## System Information Gathered

- Hardware model and CPU architecture
- macOS version
- Security tool versions and installation status
- XProtect version, installation date, and scan configuration
- VM detection warnings
- Rosetta 2 compatibility status (Apple Silicon)

## Notification Analysis

Monitors the notification database for permission changes introduced by the installed software.
