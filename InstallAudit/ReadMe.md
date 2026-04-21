# InstallAudit

A testing utility for validating software titles before deployment. Automates installation testing, monitors system and security changes, and generates macOS configuration profiles.

## What It Does

1. Installs a software title via Munki (or manual installation)
2. Monitors system changes — login items, file system, security events, notifications
3. Scans packages and binaries for malware (VirusTotal, ThreatLabs, KnockKnock)
4. Generates macOS configuration profiles (PPPC, notifications, system extensions, etc.)
5. Creates Extension Attributes
6. Uninstalls and verifies clean removal
7. Produces a comprehensive markdown test report

## Prerequisites

- **macOS** 11 or later
- **Root/administrative access**
- **Munki** client installed and configured
- **Python** 3.9+ (no external packages — pure stdlib)
- **Xcode Command Line Tools** — required for `pkgutil`, `spctl`, and other system utilities used during package analysis. Install with:
  ```bash
  xcode-select --install
  ```

### Security Tools (Recommended)

Install [Objective-See](https://objective-see.org) tools for enhanced security monitoring during testing. Huge thanks to the Objective-See team for their fantastic open-source macOS security tools!

| Tool | Purpose | Download |
|------|---------|----------|
| BlockBlock | Persistence mechanism alerts | [GitHub Releases](https://github.com/objective-see/BlockBlock/releases) |
| LuLu | Network connection monitoring | [GitHub Releases](https://github.com/objective-see/LuLu/releases) |
| RansomWhere | Ransomware behaviour detection | [GitHub Releases](https://github.com/objective-see/RansomWhere/releases) |
| OverSight | Camera/microphone monitoring | [GitHub Releases](https://github.com/objective-see/OverSight/releases) |
| ReiKey | Keyboard event monitoring | [GitHub Releases](https://github.com/objective-see/ReiKey/releases) |
| KnockKnock | Persistence mechanism detection | [GitHub Releases](https://github.com/objective-see/KnockKnock/releases) |


### API Keys (Recommended)

For enhanced malware scanning, configure API keys after installation:

| Service | Purpose | File Size Limit | Get a Key |
|---------|---------|----------------|-----------|
| VirusTotal | Package malware scanning (70+ engines) | 650MB (larger files require manual upload) | [virustotal.com](https://www.virustotal.com/) |
| ThreatLabs | Mach-O binary security analysis | 50MB per binary | [ThreatLabs](https://scry.threatlabs.protect.jamfcloud.com) |

> **ThreatLabs** API keys expire every 30 days and must be rotated. Generate a new key from the [ThreatLabs portal](https://scry.threatlabs.protect.jamfcloud.com) and update with `python3 configure.py --set-tl-key YOUR_NEW_KEY`.

## Installation

```bash
git clone [repository-url]
cd InstallAudit
```

## Configuration

Run the interactive setup wizard:

```bash
python3 configure.py --edit
```

Or use command-line options:

```bash
python3 configure.py --set-vt-key YOUR_KEY    # Set VirusTotal API key
python3 configure.py --set-tl-key YOUR_KEY    # Set ThreatLabs API key
python3 configure.py --enable threatlabs       # Enable/disable features
python3 configure.py --show                    # View current config
```

Configuration is stored at `~/.install_audit.json`. See the [Configuration & Feature Flags Guide](src/core/ReadMe.md) for full details.

## Usage

```bash
sudo python3 main.py
```

The tool guides you through the workflow interactively — catalog selection, installation, security monitoring, profile generation, and report output.

### Output

All generated files are saved to a folder named after the Munki item:

```
~/Downloads/MunkiItemName/
├── MunkiItemName.icns                    # Extracted application icon
├── Extension Attribute - MunkiName.sh    # EA script (if needed)
├── *.mobileconfig                        # Configuration profiles
└── report_timestamp.md                   # Test report
```

## Project Structure

```
InstallAudit/
├── main.py              # Entry point
├── configure.py         # Configuration management CLI
└── src/
    ├── core/            # Orchestration & configuration
    ├── munki/           # Munki installation integration
    ├── profiles/        # Config profile & recipe generation
    ├── reporting/       # Report generation & output parsing
    ├── security/        # Security scanning & monitoring
    ├── system/          # System state checks & comparisons
    └── utils/           # Shared utilities
```

## Detailed Documentation

Each module has its own ReadMe with in-depth documentation:

| Module | Description |
|--------|-------------|
| [src/core/](src/core/ReadMe.md) | Configuration management, feature flags, and main orchestration |
| [src/munki/](src/munki/ReadMe.md) | Munki and manual installation workflows |
| [src/profiles/](src/profiles/ReadMe.md) | Configuration profile generation, recipes, and Extension Attributes |
| [src/reporting/](src/reporting/ReadMe.md) | Report generation and output parsing |
| [src/security/](src/security/ReadMe.md) | VirusTotal, ThreatLabs, KnockKnock, XProtect, and security tool integration |
| [src/system/](src/system/ReadMe.md) | System checks, BTM comparisons, and notification analysis |
| [src/utils/](src/utils/ReadMe.md) | Process utilities, file helpers, and package analysis |

## Workflow Overview

1. **Pre-install capture** — BTM snapshot, security tool state, system extensions, notification baseline
2. **Catalog selection** — Munki catalog update, title enumeration, user selection
3. **Installation** — Munki-based (or manual) installation with real-time security monitoring
4. **Package analysis** — Deprecated dependency detection, security vulnerability assessment
5. **Malware scanning** — VirusTotal (packages), ThreatLabs (binaries), KnockKnock (persistence)
6. **Post-install analysis** — BTM comparison, login items, security events, system changes
7. **Uninstallation** — Clean removal and residual file detection
8. **Profile generation** — Interactive config profile creation and AutoPkg recipe output
9. **Report** — Comprehensive markdown report with all findings

## Troubleshooting

| Problem | Solution |
|---------|----------|
| BTM parsing errors | Ensure macOS 11+, run with `sudo` |
| Security tools missing | Tools are optional — script continues without them |
| Munki issues | Verify Munki client and test repo config |
| Permission denied | Must run with `sudo`; check Full Disk Access if needed |
| VirusTotal rate limits | Use an enterprise API key, or wait and retry |
| ThreatLabs timeouts | Check network; review `/tmp/threatlabs_debug.log` |
| ThreatLabs 404 errors | API key has likely expired — rotate it every 30 days via the [ThreatLabs portal](https://scry.threatlabs.protect.jamfcloud.com) |
| pkgcheck errors | Run `chmod +x src/utils/pkgcheck.sh` |

## Author

Paul Cossey
