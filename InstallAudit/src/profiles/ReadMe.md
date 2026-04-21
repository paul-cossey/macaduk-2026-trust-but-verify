# Profiles — Configuration Profile Generation

The `profiles` module analyses applications and automatically generates macOS configuration profiles and Extension Attribute scripts.

## Files

| File | Class | Purpose |
|------|-------|---------|
| `app_analyzer.py` | `AppAnalyzer` | Deep inspection of app entitlements, frameworks, code signing, and architecture |
| `profile_generator.py` | `ProfileGenerator` | Creates and manages `.mobileconfig` profile files |
| `profile_templates.py` | `ProfileTemplates` | Template structures for each profile type |
| `ea_generator.py` | — | Generates Extension Attribute shell scripts |

## Supported Profile Types

| Profile Type | Description |
|-------------|-------------|
| PPPC | Privacy Preferences Policy Control (camera, microphone, etc.) |
| Notifications | Application notification requirements |
| System Extensions | System extension allowlists |
| Kernel Extensions | Legacy kext requirements |
| Content Filters | Network content filtering |
| Screen Recording | Screen capture permissions |
| Managed Login Items | Login item management (LaunchAgents, LaunchDaemons, apps) |

## Profile Generation

### Automated Analysis

During drag-and-drop analysis, the system:

1. Analyses entitlements, frameworks, and system requirements
2. Extracts the application icon (renamed to match the Munki item name)
3. Generates profiles for all detected requirements

### Manual Profile Generation

An interactive wizard supports:

- Generating profiles for a specific application
- Creating profiles for multiple applications
- Smart reuse of information from previous analyses
- Team identifier and bundle identifier auto-completion

### Profile Merging

Duplicate Managed Login Items profiles are automatically detected and merged:

- Deduplication based on `(RuleType, RuleValue, TeamIdentifier)` tuples
- Merged profiles use the naming format `Managed Login Items - App1, App2`
- Individual PPPC, Notifications, and System Extensions profiles are preserved

### Intelligent RuleType Detection

| RuleType | Used For | Detection |
|----------|---------|-----------|
| `Label` | LaunchAgents / LaunchDaemons | URL contains `/LaunchAgents/` or `/LaunchDaemons/` |
| `BundleIdentifier` | Application bundles | URL points to `.app` bundles or non-LaunchAgent items |

## Extension Attribute Scripts

EA scripts are generated when:

1. An app uses `CFBundleVersion` instead of `CFBundleShortVersionString` for versioning
2. The app/plugin/binary is outside `/Applications`
3. Package receipts are needed for version tracking

Script types:

| Type | Version Source |
|------|---------------|
| Info.plist reader | `CFBundleVersion` or `CFBundleShortVersionString` from the app bundle |
| Package receipt reader | `pkgutil` query on installed receipt |
| Binary version reader | Version reported via command-line |

When multiple options exist (e.g., multiple receipts), the user is prompted to select.

### EA Configuration

| Setting | Description |
|---------|-------------|
| `create_ea` | Enable/disable EA generation |
| `ea_license_header` | Include BSD-3-Clause license header |
| `ea_custom_header` | Custom company name in the header |

## Rosetta 2 Detection

The app analyser detects whether an application requires Rosetta 2 on Apple Silicon:

- **Primary method:** Parses the `Format` field from `codesign` output to identify architectures
- **Fallback:** Uses `system_profiler` runtime detection
- Intel-only binaries (`x86_64`, `i386`) → Rosetta required
- Any ARM architecture (`arm64`, `arm64e`) → native Apple Silicon
