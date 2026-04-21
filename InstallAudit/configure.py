#!/usr/bin/env python3
# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Configuration management tool for InstallAudit.

Usage:
    python3 configure.py                    # Interactive setup (if no keys) or show config
    python3 configure.py --show             # View current configuration
    python3 configure.py --edit             # Edit configuration interactively
    python3 configure.py --set-vt-key KEY   # Set VirusTotal API key
    python3 configure.py --set-tl-key KEY   # Set ThreatLabs API key
    python3 configure.py --enable FEATURE   # Enable a feature
    python3 configure.py --disable FEATURE  # Disable a feature
"""

import sys
import argparse
from pathlib import Path

# Add src to path before importing local modules
sys.path.insert(0, str(Path(__file__).parent))

from src.core.config_manager import get_config  # noqa: E402

# Constants
BLANK_DISPLAY = "(blank)"


def _configure_api_keys(config):
    """Configure API keys for VirusTotal and ThreatLabs."""
    print("\n--- API Keys ---")
    print()

    current_vt = config.get_virustotal_key()
    vt_display = f"***{current_vt[-4:]}" if current_vt and len(current_vt) > 4 else "(not set)"
    vt_input = input(f"VirusTotal API Key [{vt_display}]: ").strip()
    if vt_input:
        config.set_virustotal_key(vt_input)
        print("✅ VirusTotal API key updated")

    current_tl = config.get_threatlabs_key()
    tl_display = f"***{current_tl[-4:]}" if current_tl and len(current_tl) > 4 else "(not set)"
    tl_input = input(f"ThreatLabs API Key [{tl_display}]: ").strip()
    if tl_input:
        config.set_threatlabs_key(tl_input)
        print("✅ ThreatLabs API key updated")


def _print_feature_note(key):
    """Print special notes for specific features."""
    if key == 'auto_create_profiles':
        print()
        print("Note: When enabled, configuration profiles will be automatically generated")
        print("      after application analysis. When disabled, you'll need to manually")
        print("      trigger profile generation through the wizard.")
        print()
    elif key == 'auto_install_dragged_media':
        print()
        print("Note: When enabled, dragged installer media (PKG, DMG, archives) will be")
        print("      automatically installed to /Applications during manual installation mode.")
        print("      PKG files use 'sudo installer', app bundles are copied, archives unpacked.")
        print()
    elif key == 'knockknock_use_virustotal':
        print()
        print("⚠️  Warning: KnockKnock VirusTotal integration will consume API quota.")
        print("    Each scan may check dozens of persistence items against VirusTotal.")
        print("    This can significantly impact your daily VirusTotal API quota.")
        print()


def _configure_single_feature(config, key, description, current):
    """Configure a single feature toggle."""
    current_str = "yes" if current else "no"
    _print_feature_note(key)

    user_input = input(f"{description} [{current_str}]: ").strip().lower()

    if user_input in ['yes', 'y', 'true', '1']:
        config.set('features', key, value=True)
        print(f"✅ {description}: enabled")
    elif user_input in ['no', 'n', 'false', '0']:
        config.set('features', key, value=False)
        print(f"✅ {description}: disabled")


def _configure_features(config):
    """Configure feature toggles."""
    print("\n--- Features (yes/no) ---")
    print()

    features = [
        ('extract_icon', 'Extract application icons', config.is_icon_extraction_enabled()),
        ('create_ea', 'Create Extension Attributes', config.is_ea_creation_enabled()),
        ('ea_license_header', 'Include license header in EAs', config.is_ea_license_header_enabled()),
        ('auto_create_profiles', 'Auto-create configuration profiles', config.is_auto_create_profiles_enabled()),
        ('auto_install_dragged_media', 'Auto-install dragged installer media', config.is_auto_install_enabled()),
        ('enable_threatlabs_scan', 'Enable ThreatLabs scanning', config.is_threatlabs_enabled()),
        ('knockknock_use_virustotal', 'KnockKnock VirusTotal integration', config.is_knockknock_virustotal_enabled())
    ]

    for key, description, current in features:
        _configure_single_feature(config, key, description, current)


def _configure_ea_header(config):
    """Configure custom EA header company name."""
    print("\n--- Custom Company Name for EA License ---")
    print()
    current_header = config.get_ea_custom_header()
    header_display = f"'{current_header}'" if current_header else BLANK_DISPLAY

    print("This sets the company name in the BSD-3-Clause license header.")
    print("Leave blank to omit company name from header.")
    print()
    header_input = input(f"Company name [{header_display}]: ").strip()
    if header_input:
        config.set('features', 'ea_custom_header', value=header_input)
        print(f"✅ Company name updated to '{header_input}'")


def _configure_defaults(config):
    """Configure default settings."""
    print("\n--- Default Settings ---")
    print()

    # Log Lookback Minutes
    current_lookback = config.get_default_log_lookback_minutes()
    print("Default time (in minutes) to search unified logs for security events.")
    print("This is used as the default when starting tests. Users can override this.")
    lookback_input = input(f"Log lookback period in minutes [{current_lookback}]: ").strip()
    if lookback_input:
        try:
            lookback_value = int(lookback_input)
            if lookback_value > 0:
                config.set('defaults', 'log_lookback_minutes', value=lookback_value)
                print(f"✅ Log lookback period updated to {lookback_value} minutes")
            else:
                print("⚠️  Value must be greater than 0. Keeping current value.")
        except ValueError:
            print("⚠️  Invalid number. Keeping current value.")

    # Default Catalog
    print()
    current_catalog = config.get_default_catalog()
    print("Default Munki catalog to use for software installation testing.")
    print("This is used as the default during catalog selection. Users can override this.")
    catalog_input = input(f"Default catalog [{current_catalog}]: ").strip()
    if catalog_input:
        config.set('defaults', 'catalog', value=catalog_input)
        print(f"✅ Default catalog updated to '{catalog_input}'")

    # Munki Manifest Name
    print()
    current_manifest = config.get_munki_manifest_name()
    print("Name of the Munki manifest used for installation testing.")
    print("This is the plist filename (without .plist extension) in /Library/Managed Installs/manifests/.")
    manifest_input = input(f"Munki manifest name [{current_manifest}]: ").strip()
    if manifest_input:
        # Strip .plist extension if user included it
        manifest_input = manifest_input.removesuffix('.plist')
        config.set('defaults', 'munki_manifest_name', value=manifest_input)
        print(f"✅ Munki manifest name updated to '{manifest_input}'")

    # Default Save Location
    print()
    current_save = config.get_default_save_location()
    print("Default location to save reports and configuration profiles.")
    print("This is used as the default when saving output files. Users can override this.")
    save_input = input(f"Default save location [{current_save}]: ").strip()
    if save_input:
        config.set('defaults', 'save_location', value=save_input)
        print(f"✅ Default save location updated to '{save_input}'")

    # Profile Organization
    print()
    current_org = config.get_profile_organization()
    org_display = f"'{current_org}'" if current_org else BLANK_DISPLAY
    print("Organization name for configuration profile PayloadOrganization field.")
    print("This appears in System Settings when viewing installed profiles.")
    org_input = input(f"Profile organization [{org_display}]: ").strip()
    if org_input:
        config.set('defaults', 'profile_organization', value=org_input)
        print(f"✅ Profile organization updated to '{org_input}'")

    # Profile Identifier Prefix
    print()
    current_prefix = config.get_profile_identifier_prefix()
    prefix_display = f"'{current_prefix}'" if current_prefix else BLANK_DISPLAY
    print("Reverse domain for configuration profile PayloadIdentifier field.")
    print("Example: 'com.company' or 'uk.co.company'")
    prefix_input = input(f"Profile identifier prefix [{prefix_display}]: ").strip()
    if prefix_input:
        config.set('defaults', 'profile_identifier_prefix', value=prefix_input)
        print(f"✅ Profile identifier prefix updated to '{prefix_input}'")

    # Report Title
    print()
    current_title = config.get_report_title()
    print("Title for markdown test reports (appears as # heading at top of report).")
    title_input = input(f"Report title [{current_title}]: ").strip()
    if title_input:
        config.set('defaults', 'report_title', value=title_input)
        print(f"✅ Report title updated to '{title_input}'")


def _configure_installation_method(config):
    """Configure installation method."""
    print("\n--- Installation Method ---")
    print()
    current_method = config.get_installation_method()
    print(f"Current: {current_method}")
    print()
    print("Available methods:")
    print("  1. munki_local     - Use local Munki manifest (default)")
    print("  2. manual          - User performs manual installation")
    print("  3. munki_standard  - Standard Munki server workflow (select existing manifest)")
    print()
    method_input = input(f"Installation method (1/2/3) [{current_method}]: ").strip()

    method_map = {
        '1': 'munki_local',
        '2': 'manual',
        '3': 'munki_standard',
        'munki_local': 'munki_local',
        'manual': 'manual',
        'munki_standard': 'munki_standard'
    }

    if method_input in method_map:
        new_method = method_map[method_input]
        config.set('defaults', 'installation_method', value=new_method)
        print(f"✅ Installation method updated to '{new_method}'")


def interactive_config():
    """Interactive configuration editor."""
    config = get_config()

    print("\n" + "=" * 60)
    print("InstallAudit - Configuration Editor")
    print("=" * 60)
    print("\nPress Enter to keep current value, or type new value to change.")
    print("=" * 60)

    _configure_api_keys(config)
    _configure_features(config)
    _configure_ea_header(config)
    _configure_defaults(config)
    _configure_installation_method(config)

    # Save configuration
    print("\n" + "=" * 60)
    if config.save_config():
        print(f"✅ Configuration saved to {config.config_path}")
    else:
        print("❌ Failed to save configuration")
    print("=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Manage InstallAudit configuration'
    )
    parser.add_argument('--show', action='store_true',
                        help='Show current configuration')
    parser.add_argument('--edit', action='store_true',
                        help='Edit configuration interactively')
    parser.add_argument('--set-vt-key', metavar='KEY',
                        help='Set VirusTotal API key')
    parser.add_argument('--set-tl-key', metavar='KEY',
                        help='Set ThreatLabs API key')
    parser.add_argument('--enable', metavar='FEATURE',
                        choices=['icon', 'ea', 'ea-license', 'threatlabs', 'knockknock-vt'],
                        help='Enable a feature')
    parser.add_argument('--disable', metavar='FEATURE',
                        choices=['icon', 'ea', 'ea-license', 'threatlabs', 'knockknock-vt'],
                        help='Disable a feature')

    args = parser.parse_args()

    config = get_config()

    # Handle actions
    if args.set_vt_key:
        config.set_virustotal_key(args.set_vt_key)
        config.save_config()
        print("✅ VirusTotal API key set")
        return

    if args.set_tl_key:
        config.set_threatlabs_key(args.set_tl_key)
        config.save_config()
        print("✅ ThreatLabs API key set")
        return

    feature_map = {
        'icon': 'extract_icon',
        'ea': 'create_ea',
        'ea-license': 'ea_license_header',
        'threatlabs': 'enable_threatlabs_scan',
        'knockknock-vt': 'knockknock_use_virustotal'
    }

    if args.enable:
        config.set('features', feature_map[args.enable], value=True)
        config.save_config()
        print(f"✅ Feature '{args.enable}' enabled")
        return

    if args.disable:
        config.set('features', feature_map[args.disable], value=False)
        config.save_config()
        print(f"✅ Feature '{args.disable}' disabled")
        return

    if args.edit:
        interactive_config()
        return

    if args.show:
        config.print_config()
        return

    # Default action when run with no arguments:
    # If API keys are not configured IN THE CONFIG FILE, run interactive setup
    # Otherwise, show configuration
    # Check config file directly, not environment variables
    vt_key_in_config = config.get('api_keys', 'virustotal', default='')
    tl_key_in_config = config.get('api_keys', 'threatlabs', default='')

    if not vt_key_in_config and not tl_key_in_config:
        # First-time setup - no keys in config file
        print("\n" + "=" * 60)
        print("Welcome to Paul Cosseynfiguration!")
        print("=" * 60)
        print("\nNo API keys found in config file. Let's set up your configuration.")
        print("You can press Enter to skip any setting.\n")
        input("Press Enter to continue...")
        interactive_config()
    else:
        # Keys are configured in file, just show current config
        config.print_config()


if __name__ == '__main__':
    main()
