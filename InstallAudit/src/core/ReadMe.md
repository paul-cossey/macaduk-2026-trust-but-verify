# Core — Orchestration & Configuration

The `core` module contains the main orchestration logic and all configuration management for the tool.

## Files

| File | Class / Exports | Purpose |
|------|----------------|---------|
| `auto_update_tester.py` | `AutoUpdateTester` | Main orchestrator — drives the entire test workflow |
| `config_manager.py` | `get_config()` | Manages `~/.install_audit.json` — API keys, feature flags, defaults |
| `config.py` | `security_tools`, `event_formatting`, `report_config` | Legacy configuration dictionaries for security tools and report formatting |
| `exceptions.py` | Custom exceptions | `CatalogError`, `InstallationError`, etc. |

## Configuration File

**Path:** `~/.install_audit.json`

### Managing Configuration

Interactive editor:

```bash
python3 configure.py --edit
```

Command-line:

```bash
python3 configure.py --show                    # View current config
python3 configure.py --set-vt-key YOUR_KEY     # Set VirusTotal API key
python3 configure.py --set-tl-key YOUR_KEY     # Set ThreatLabs API key
python3 configure.py --enable FEATURE          # Enable a feature
python3 configure.py --disable FEATURE         # Disable a feature
```

### Configuration Structure

```json
{
  "api_keys": {
    "virustotal": "your-api-key-here",
    "threatlabs": "your-api-key-here"
  },
  "features": {
    "extract_icon": true,
    "create_ea": true,
    "ea_license_header": true,
    "ea_custom_header": "",
    "auto_create_profiles": true,
    "enable_threatlabs_scan": true,
    "knockknock_use_virustotal": false
  },
  "defaults": {
    "installation_method": "munki_local",
    "log_lookback_minutes": 20,
    "catalog": "testing",
    "munki_manifest_name": "auto-update",
    "save_location": "~/Downloads",
    "profile_organization": "",
    "profile_identifier_prefix": "",
    "report_title": "InstallAudit Software Title Installation Test Report"
  }
}
```

> Environment variables `VIRUSTOTAL_API_KEY` and `THREATLABS_API_KEY` take precedence over config file values.

### Feature Flags

Available features for `--enable` / `--disable`:

| Flag | Config Key | Default | Description |
|------|-----------|---------|-------------|
| `icon` | `extract_icon` | `true` | Extract application icons during testing |
| `ea` | `create_ea` | `true` | Generate Extension Attribute scripts |
| `ea-license` | `ea_license_header` | `true` | Include BSD-3-Clause license header in EAs |
| `auto-create-profiles` | `auto_create_profiles` | `true` | Auto-generate config profiles after analysis |
| `threatlabs` | `enable_threatlabs_scan` | `true` | Enable ThreatLabs binary scanning |
| `knockknock-vt` | `knockknock_use_virustotal` | `false` | VirusTotal integration in KnockKnock scans |

### Feature Flag Integration Points

| Feature | Checked In | Config Method |
|---------|-----------|---------------|
| Icon extraction | `src/security/event_processor.py` | `config.is_icon_extraction_enabled()` |
| EA creation | `src/core/auto_update_tester.py` | `config.is_ea_creation_enabled()` |
| EA license header | `src/profiles/ea_generator.py` | `config.is_ea_license_header_enabled()` |
| Auto-create profiles | `src/core/auto_update_tester.py` | `config.is_auto_create_profiles_enabled()` |
| ThreatLabs scanning | `src/munki/installer.py` | `config.is_threatlabs_enabled()` |

When disabled, each feature prints a skip message (e.g., "Icon extraction disabled in config — skipping").

### Defaults Reference

| Key | Default | Description |
|-----|---------|-------------|
| `installation_method` | `munki_local` | `munki_local`, `manual`, or `munki_standard` (placeholder) |
| `log_lookback_minutes` | `20` | How far back to search unified logs (minutes) |
| `catalog` | `testing` | Default Munki catalog |
| `munki_manifest_name` | `auto-update` | Manifest plist name (without `.plist`) |
| `save_location` | `~/Downloads` | Where to save reports and profiles |
| `profile_organization` | `""` | `PayloadOrganization` in generated profiles |
| `profile_identifier_prefix` | `""` | Reverse-domain prefix for `PayloadIdentifier` |
| `report_title` | `"InstallAudit..."` | Markdown heading of test reports |

### Security

- API keys are masked when displayed (`--show` reveals only last 4 characters)
- Config file lives in your home directory with standard permissions
- Environment variables take precedence for CI/CD usage

### Troubleshooting

If the config file doesn't exist, it's created automatically with defaults on first run. Verify syntax with:

```bash
python3 configure.py --show
```
