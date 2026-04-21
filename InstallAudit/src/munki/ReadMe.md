# Munki — Installation Integration

The `munki` module handles software installation (and uninstallation) via Munki or via manual user-driven workflows.

## Files

| File | Class | Purpose |
|------|-------|---------|
| `catalog_manager.py` | `CatalogManager` | Reads and parses Munki catalogs, enumerates available titles |
| `manifest_manager.py` | `ManifestManager` | Discovers, resolves and manipulates Munki manifests |
| `installer.py` | `MunkiInstaller` | Automated Munki-based installation and uninstallation |
| `manual_installer.py` | `ManualInstaller` | User-driven installation with security scanning (no Munki) |
| `installation_validator.py` | `InstallationValidator` | Shared validation logic used by both installers |

## Installation Methods

The tool supports three installation methods, configurable in `~/.install_audit.json`:

### `munki_local` (Default)

Designed for machines that use a **local-only** Munki setup (no server).

1. Resets (deletes) the local manifest before each run
2. Updates and parses the Munki catalog
3. Presents available titles for user selection
4. Adds the selected title to the local manifest
5. Runs `managedsoftwareupdate` for installation
6. Monitors for installation failures (package-level error detection)
7. Performs security scanning (VirusTotal, ThreatLabs, KnockKnock)
8. Runs uninstallation and verifies clean removal

Typical local-only manifest structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>managed_installs</key>
    <array/>
    <key>managed_uninstalls</key>
    <array/>
</dict>
</plist>
```

### `munki_standard`

Designed for machines managed by a **Munki server** where manifests are synced from the server.

1. Lists available manifests in `/Library/Managed Installs/manifests/`
2. Lets the user select which manifest to modify (default from config)
3. Updates and parses the Munki catalog, presents available titles
4. Adds the selected title to `managed_installs` / `managed_uninstalls`
5. Runs `managedsoftwareupdate` for installation
6. Same security scanning, profile generation and uninstallation as `munki_local`

**Manifest discovery** handles filenames with or without the `.plist` extension
and supports special characters (spaces, serial-number formats, etc.).

> **Recommendation:** Keep the server-side manifest empty (catalogs only) so
> that this script can control what gets added locally without the server
> overriding it during the next Munki run.

Typical empty server-side manifest:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>catalogs</key>
    <array>
        <string>testing</string>
    </array>
</dict>
</plist>
```

The script will add `managed_installs` and `managed_uninstalls` keys
automatically when they are not present.

### `manual`

1. User performs the installation themselves (drag-and-drop, pkg, etc.)
2. Security monitoring runs in parallel — same scans as the Munki workflow
3. No automated uninstallation step
4. Useful for testing software not available via Munki

## Manifest Management

`ManifestManager` provides helpers for working with manifests on disk:

| Method | Purpose |
|--------|---------|
| `get_available_manifests()` | Scans the manifests directory and returns valid plist filenames |
| `resolve_manifest_path(name)` | Resolves a manifest name to its on-disk path, handling missing `.plist` extension |
| `select_manifest_interactive()` | Interactive numbered menu for picking a manifest (uses config default) |

## Catalog Selection

The default catalog is set in the configuration file and can be changed
interactively at runtime.  `CatalogManager.select_catalog_interactive()`
presents a numbered list of available catalogs.

## Installation Failure Detection

The Munki installer detects failures automatically:

- **Package-level failures** — e.g., `Install of X.pkg failed with return code 1`
- **Installation errors** — `installation failed` and related patterns
- **Return code monitoring** — parses `managedsoftwareupdate` output

When a failure is detected, execution stops immediately to allow investigation.

## Shared Validation (`InstallationValidator`)

Common logic shared between `MunkiInstaller` and `ManualInstaller`:

- KnockKnock baseline scanning setup (before/after comparison)
- Post-installation validation steps
- Security scan orchestration
