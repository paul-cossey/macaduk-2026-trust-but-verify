# Security — Scanning & Monitoring

The `security` module provides real-time security monitoring, malware scanning, and persistence detection during software installation testing.

## Files

| File | Class | Purpose |
|------|-------|---------|
| `monitoring.py` | `SecurityMonitoring` | Real-time security event monitoring during installation |
| `tool_manager.py` | `SecurityToolManager` | Manages security tool lifecycle (detect, reset, verify) |
| `event_processor.py` | `SecurityEventProcessor` | Parses and analyses security events from unified logs |
| `virustotal_analyzer.py` | — | VirusTotal API integration for package malware scanning |
| `threatlabs_scanner.py` | `ThreatLabsScanner` | ThreatLabs API integration for Mach-O binary analysis |
| `knockknock_scanner.py` | `KnockKnockScanner` | KnockKnock CLI integration for persistence mechanism detection |

## Security Tools

| Tool | Status | Purpose |
|------|--------|---------|
| RansomWhere | Active (reset between tests) | Ransomware behaviour detection |
| OverSight | Active | Camera/microphone access monitoring |
| ReiKey | Active | Keyboard event monitoring |
| DHS | Active | System security scanning |
| BlockBlock | Monitored (unified log) | Persistence mechanism alerts |
| LuLu | Monitored (unified log) | Network connection monitoring + VT analysis |
| XProtect | Monitored (unified log) | Apple's built-in malware protection |
| KnockKnock | Monitored (before/after) | Persistence mechanism detection |

## VirusTotal Integration

- Scans downloaded PKG files using 70+ antivirus engines
- Automatic SHA-256 hash lookup; submits new files for analysis (up to 650MB)
- Files over 650MB require manual upload
- Scans URLs and IPs detected by LuLu network monitoring
- 5-minute analysis timeout; direct links to VT reports

### Configuration

```bash
python3 configure.py --set-vt-key YOUR_API_KEY
```

> Public API keys have rate limits — enterprise keys recommended for heavy use.

## ThreatLabs Integration

- Scans Mach-O binaries extracted during installation
- SHA-256 hash lookup with intelligent caching (avoids resubmission)
- Parallel scanning via `ThreadPoolExecutor` with configurable batch sizes (default: 100)
- Binaries over 50MB are automatically skipped
- Threat levels: clean / suspicious / malicious
- YARA rule matching and developer info extraction
- Debug log: `/tmp/threatlabs_debug.log`

### Configuration

```bash
python3 configure.py --set-tl-key YOUR_KEY
python3 configure.py --enable threatlabs      # or --disable
```

### API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/api/v1/submissions/upload` | Binary submission |
| `/api/v1/submissions/{id}/status` | Analysis polling |
| `/api/v1/submissions/{id}/results` | Results retrieval |
| `/api/v1/hashes/sha256/{hash}/exists` | Hash existence check |

Base URL: `https://api.scry.threatlabs.protect.jamfcloud.com`

## KnockKnock Integration

- Before/after scanning with KnockKnock CLI
- Detects new, modified, and removed persistence items
- Covers launch agents/daemons, browser extensions, login items, kernel extensions, and more
- Optional VirusTotal scanning of new persistence items (`knockknock_use_virustotal` — disabled by default to preserve API quota)

## XProtect Monitoring

- Uses `sudo xprotect version` and `sudo xprotect status`
- Tracks version, installation date, launch/background scan config
- Monitors unified logs for real-time malware detection and quarantine events
