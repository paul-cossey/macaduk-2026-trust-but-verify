# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Configuration manager for InstallAudit.

Handles reading/writing configuration from ~/.install_audit.json
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

# Default configuration file path
CONFIG_FILE = Path.home() / '.install_audit.json'

# Default configuration structure
DEFAULT_CONFIG = {
    'api_keys': {
        'virustotal': '',
        'threatlabs': ''
    },
    'features': {
        'extract_icon': True,
        'create_ea': True,
        'ea_license_header': True,
        'ea_custom_header': '',
        'enable_threatlabs_scan': True,
        'knockknock_use_virustotal': False,
        'auto_create_profiles': True,
        'auto_install_dragged_media': False
    },
    'defaults': {
        'log_lookback_minutes': 20,
        'catalog': 'testing',
        'munki_manifest_name': 'auto-update',
        'save_location': '~/Downloads',
        'profile_organization': '',
        'profile_identifier_prefix': '',
        'installation_method': 'munki_local',
        'report_title': 'InstallAudit Software Title Installation Test Report'
    }
}


class ConfigManager:
    """Manages configuration file for InstallAudit."""

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize config manager.

        Args:
            config_path: Path to config file (defaults to ~/.install_audit.json)
        """
        self.config_path = config_path or CONFIG_FILE
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.

        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            # Create default config file
            self._create_default_config()
            return DEFAULT_CONFIG.copy()

        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f) or {}

            # Merge with defaults to ensure all keys exist
            return self._merge_with_defaults(config)

        except Exception as e:
            print(f"Warning: Error loading config from {self.config_path}: {e}")
            print("Using default configuration")
            return DEFAULT_CONFIG.copy()

    def _merge_with_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge user config with defaults to ensure all keys exist.

        Args:
            config: User configuration

        Returns:
            Merged configuration
        """
        merged = DEFAULT_CONFIG.copy()

        # Merge API keys
        if 'api_keys' in config:
            merged['api_keys'].update(config['api_keys'])

        # Merge features
        if 'features' in config:
            merged['features'].update(config['features'])

        # Merge defaults
        if 'defaults' in config:
            merged['defaults'].update(config['defaults'])

        return merged

    def _create_default_config(self):
        """Create default configuration file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"✅ Created default configuration file: {self.config_path}")
            print(f"📝 Please edit {self.config_path} to add your API keys")
        except Exception as e:
            print(f"Warning: Could not create config file {self.config_path}: {e}")

    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config to {self.config_path}: {e}")
            return False

    def get(self, *keys, default=None):
        """
        Get configuration value using nested keys.

        Args:
            *keys: Nested keys to traverse
            default: Default value if key not found

        Returns:
            Configuration value or default

        Example:
            config.get('api_keys', 'virustotal')
            config.get('features', 'extract_icon')
        """
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, *keys, value):
        """
        Set configuration value using nested keys.

        Args:
            *keys: Nested keys to traverse
            value: Value to set

        Example:
            config.set('api_keys', 'virustotal', value='abc123')
            config.set('features', 'extract_icon', value=False)
        """
        if len(keys) < 1:
            return

        # Navigate to parent dict
        current = self.config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        # Set the value
        current[keys[-1]] = value

    # Convenience methods for API keys
    def get_virustotal_key(self) -> str:
        """Get VirusTotal API key."""
        # Check environment variable first, then config file
        return os.environ.get('VIRUSTOTAL_API_KEY') or self.get('api_keys', 'virustotal', default='')

    def get_threatlabs_key(self) -> str:
        """Get ThreatLabs API key."""
        # Check environment variable first, then config file
        return os.environ.get('THREATLABS_API_KEY') or self.get('api_keys', 'threatlabs', default='')

    def set_virustotal_key(self, key: str):
        """Set VirusTotal API key."""
        self.set('api_keys', 'virustotal', value=key)

    def set_threatlabs_key(self, key: str):
        """Set ThreatLabs API key."""
        self.set('api_keys', 'threatlabs', value=key)

    # Convenience methods for features
    def is_icon_extraction_enabled(self) -> bool:
        """Check if icon extraction is enabled."""
        return self.get('features', 'extract_icon', default=True)

    def is_ea_creation_enabled(self) -> bool:
        """Check if EA creation is enabled."""
        return self.get('features', 'create_ea', default=True)

    def is_ea_license_header_enabled(self) -> bool:
        """Check if EA license header is enabled."""
        return self.get('features', 'ea_license_header', default=True)

    def get_ea_custom_header(self) -> str:
        """Get custom company name for EA license header."""
        return self.get('features', 'ea_custom_header', default='')

    def is_threatlabs_enabled(self) -> bool:
        """Check if ThreatLabs scanning is enabled."""
        return self.get('features', 'enable_threatlabs_scan', default=True)

    def is_knockknock_virustotal_enabled(self) -> bool:
        """Check if KnockKnock VirusTotal integration is enabled."""
        return self.get('features', 'knockknock_use_virustotal', default=False)

    def is_auto_create_profiles_enabled(self) -> bool:
        """Check if automatic configuration profile creation is enabled."""
        return self.get('features', 'auto_create_profiles', default=True)

    def is_auto_install_enabled(self) -> bool:
        """Check if automatic installation of dragged media is enabled."""
        return self.get('features', 'auto_install_dragged_media', default=False)

    def get_default_log_lookback_minutes(self) -> int:
        """Get default log lookback period in minutes."""
        return self.get('defaults', 'log_lookback_minutes', default=20)

    def get_default_catalog(self) -> str:
        """Get default Munki catalog name."""
        return self.get('defaults', 'catalog', default='testing')

    def get_munki_manifest_name(self) -> str:
        """Get Munki manifest filename (without .plist extension)."""
        return self.get('defaults', 'munki_manifest_name', default='auto-update')

    def get_default_save_location(self) -> str:
        """Get default save location for reports and profiles."""
        return self.get('defaults', 'save_location', default='~/Downloads')

    def get_profile_organization(self) -> str:
        """Get profile organization name."""
        return self.get('defaults', 'profile_organization', default='')

    def get_profile_identifier_prefix(self) -> str:
        """Get profile identifier prefix (reverse domain)."""
        return self.get('defaults', 'profile_identifier_prefix', default='')

    def get_installation_method(self) -> str:
        """Get installation method (munki_local, manual, or munki_standard)."""
        return self.get('defaults', 'installation_method', default='munki_local')

    def get_report_title(self) -> str:
        """Get markdown report title."""
        return self.get('defaults', 'report_title', default='InstallAudit Software Title Installation Test Report')

    def print_config(self):
        """Print current configuration (masking API keys)."""
        print("\n" + "=" * 60)
        print("Current Configuration")
        print("=" * 60)
        print(f"\nConfig file: {self.config_path}")
        print("\nAPI Keys:")

        vt_key = self.get_virustotal_key()
        tl_key = self.get_threatlabs_key()

        print(f"  VirusTotal: {'*' * 20 if vt_key else '(not set)'}")
        print(f"  ThreatLabs: {'*' * 20 if tl_key else '(not set)'}")

        print("\nFeatures:")
        print(f"  Extract Icon:            {self.is_icon_extraction_enabled()}")
        print(f"  Create EA:               {self.is_ea_creation_enabled()}")
        print(f"  EA License Header:       {self.is_ea_license_header_enabled()}")
        print(f"  Auto Create Profiles:    {self.is_auto_create_profiles_enabled()}")
        print(f"  Auto Install Media:      {self.is_auto_install_enabled()}")

        custom_header = self.get_ea_custom_header()
        if custom_header:
            print(f"  EA Company Name:         '{custom_header}'")
        else:
            print("  EA Company Name:         (not set)")

        print(f"  ThreatLabs Scanning:     {self.is_threatlabs_enabled()}")
        print(f"  KnockKnock VirusTotal:   {self.is_knockknock_virustotal_enabled()}")

        print("\nDefaults:")
        print(f"  Installation Method:     {self.get_installation_method()}")
        print(f"  Log Lookback (minutes):  {self.get_default_log_lookback_minutes()}")
        print(f"  Catalog:                 {self.get_default_catalog()}")
        print(f"  Munki Manifest:          {self.get_munki_manifest_name()}")
        print(f"  Report Title:            {self.get_report_title()}")
        print()


# Global config instance
_config_instance = None


def get_config(reload: bool = False) -> ConfigManager:
    """
    Get global config instance.

    Args:
        reload: If True, reload config from file

    Returns:
        ConfigManager instance
    """
    global _config_instance

    if _config_instance is None or reload:
        _config_instance = ConfigManager()

    return _config_instance
