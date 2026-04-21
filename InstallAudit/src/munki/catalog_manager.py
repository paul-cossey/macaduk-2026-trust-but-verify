# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Catalog reading and parsing methods for InstallAudit.
"""

import os
import plistlib
import logging

logger = logging.getLogger(__name__)


class CatalogManager:
    """Handles reading and parsing of Munki catalog files."""

    def __init__(self, catalog_name="testing"):
        """Initialize CatalogManager with catalog path."""
        self.catalog_name = catalog_name
        self.catalog_path = f"/Library/Managed Installs/catalogs/{catalog_name}"

    def get_available_catalogs(self):
        """Get list of available catalog files."""
        catalog_dir = "/Library/Managed Installs/catalogs"
        try:
            if not os.path.exists(catalog_dir):
                logger.error(f"Catalog directory not found: {catalog_dir}")
                return []

            catalogs = []
            for file in os.listdir(catalog_dir):
                file_path = os.path.join(catalog_dir, file)
                # Check if it's a file and not a directory
                if os.path.isfile(file_path):
                    # Try to verify it's a valid plist catalog file
                    try:
                        with open(file_path, 'rb') as f:
                            plistlib.load(f)
                        catalogs.append(file)
                    except Exception:
                        # Skip files that aren't valid plists
                        continue

            return sorted(catalogs)
        except Exception as e:
            logger.error(f"Error listing catalogs: {e}")
            return []

    def set_catalog(self, catalog_name):
        """Set the catalog to use."""
        self.catalog_name = catalog_name
        self.catalog_path = f"/Library/Managed Installs/catalogs/{catalog_name}"
        print(f"Catalog set to: {catalog_name}")

    def select_catalog_interactive(self):
        """Interactive catalog selection interface."""
        from ..core.config_manager import get_config
        config = get_config()
        default_catalog = config.get_default_catalog()

        catalogs = self.get_available_catalogs()

        if not catalogs:
            print(f"❌ No valid catalogs found. Using default '{default_catalog}' catalog.")
            print("   (This may not exist yet - it will be created during catalog update)")
            return default_catalog

        if len(catalogs) == 1:
            catalog = catalogs[0]
            print(f"✅ Only one catalog available: {catalog}")
            return catalog

        print("\nAvailable Munki catalogs:")
        print("-" * 30)
        for idx, catalog in enumerate(catalogs, 1):
            print(f"{idx}. {catalog}")
        print("-" * 30)

        while True:
            try:
                choice = input(f"\nEnter the number of the catalog to use (or press Enter for '{default_catalog}'): ").strip()

                if not choice:  # Default to configured catalog
                    return default_catalog

                selection = int(choice) - 1
                if 0 <= selection < len(catalogs):
                    selected_catalog = catalogs[selection]
                    print(f"Selected catalog: {selected_catalog}")
                    return selected_catalog
                else:
                    print("❌ Invalid selection. Please try again.")
            except ValueError:
                print("❌ Please enter a valid number.")
            except KeyboardInterrupt:
                print("\n\nCancelled by user")
                return None

    def _read_catalog(self):
        """Read the configured catalog"""
        try:
            print(f"\nReading {self.catalog_name} catalog from: {self.catalog_path}")
            if os.path.exists(self.catalog_path):
                with open(self.catalog_path, 'rb') as f:
                    catalog_data = plistlib.load(f)
                print(
                    f"✅ Successfully read {self.catalog_name} catalog with "
                    f"{len(catalog_data)} items"
                )
                return catalog_data
            else:
                logger.error(f"Catalog file not found: {self.catalog_path}")
                print(f"❌ Catalog file not found: {self.catalog_path}")
                return None
        except Exception as e:
            logger.error(f"Error reading catalog: {e}")
            print(f"❌ Error reading catalog: {e}")
            return None

    def _detect_architecture(self, item):
        """Detect architecture from catalog item metadata."""
        # Check for supported_architectures first (most reliable)
        if 'supported_architectures' in item:
            archs = item['supported_architectures']
            if archs:  # Make sure the list isn't empty
                return ','.join(archs)
            else:
                return "unspecified"

        # Check installer_item_location for architecture hints
        if 'installer_item_location' in item:
            location = item['installer_item_location'].lower()
            if 'arm64' in location:
                return 'arm64'
            elif 'x86_64' in location:
                return 'x86_64'
            elif 'intel' in location:
                return 'x86_64'
            elif 'universal' in location:
                return 'universal'
            else:
                return "unspecified"

        # Check if this is actually a universal binary by looking at other fields
        # Some packages may have universal in the name or description
        if any('universal' in str(item.get(field, '')).lower()
               for field in ['name', 'display_name', 'description']):
            return 'universal'

        return "unspecified"

    def _parse_catalog_items(self, catalog_data):
        """Parse catalog items and group by architecture"""
        parsed_items = []
        seen_items = {}

        for item in catalog_data:
            name = item.get('name', 'Unknown')
            version = item.get('version', 'Unknown')
            arch = self._detect_architecture(item)

            key = f"{name}-{version}"
            if key not in seen_items:
                seen_items[key] = {
                    'name': name,
                    'version': version,
                    'architectures': {arch},
                    'catalog_items': [item]
                }
            else:
                seen_items[key]['architectures'].add(arch)
                seen_items[key]['catalog_items'].append(item)

        # Convert to list and format architectures
        for item_data in seen_items.values():
            archs = item_data['architectures']
            if len(archs) > 1:
                arch_str = f"({', '.join(sorted(archs))})"
            else:
                arch_str = f"({next(iter(archs))})"

            parsed_items.append({
                'name': item_data['name'],
                'version': item_data['version'],
                'architecture': arch_str,
                'catalog_items': item_data['catalog_items']
            })

        return parsed_items

    def _validate_catalog_item(self, item):
        """Validate catalog item details and return validation results"""
        validation_results = []

        # Record uninstall method
        uninstall_method = item.get('uninstall_method', 'Not specified')
        validation_results.append(f"Uninstall Method: {uninstall_method}")

        # Check installs array
        installs = item.get('installs', [])
        if not installs:
            validation_results.append(
                "ℹ️ Title has no installs array. "
                "Extension Attribute is Needed"
            )
            return validation_results

        validation_results.append(
            f"Found {len(installs)} item(s) in installs array"
        )

        # Validate each installs item and collect minosversions
        minosversions = []
        highest_minosversion = None

        for index, install in enumerate(installs, 1):
            item_results, install_min_os = self._validate_installs_item(
                install, index, item.get('version')
            )
            validation_results.extend(item_results)

            # Track minosversions
            if install_min_os:
                minosversions.append(install_min_os)
                if (highest_minosversion is None
                        or self._compare_versions(install_min_os, highest_minosversion) > 0):
                    highest_minosversion = install_min_os

        # Validate OS versions
        os_validation_results = self._validate_os_versions(
            minosversions, highest_minosversion, item.get('minimum_os_version')
        )
        validation_results.extend(os_validation_results)

        return validation_results

    def _validate_installs_item(self, install, index, item_version):
        """Validate a single installs array item"""
        results = [f"\nValidating installs array item {index}:"]

        # Check minosversion
        install_min_os = install.get('minosversion')
        if install_min_os:
            results.append(f"Found minosversion: {install_min_os}")
        else:
            results.append("Found minosversion: ")

        # Check version_comparison_key
        version_comparison_key = install.get('version_comparison_key')
        if version_comparison_key is None:
            results.append(
                "ℹ️ No version_comparison_key specified in installs item. "
                "Please correct..."
            )
        else:
            install_version = install.get(version_comparison_key)
            if install_version is None:
                results.append(
                    f"❌ Error: {version_comparison_key} not found in installs item"
                )
            elif item_version is None:
                results.append("❌ Error: version not found in catalog item")
            elif install_version != item_version:
                results.append(
                    f"❌ Error: {version_comparison_key} version "
                    f"({install_version}) does not match item version ({item_version})"
                )
            else:
                results.append(
                    f"✅ {version_comparison_key} version matches "
                    f"item version ({item_version})"
                )

        # Add additional details
        if 'path' in install:
            results.append(f"Path: {install['path']}")
        if 'type' in install:
            results.append(f"Type: {install['type']}")
        if 'CFBundleIdentifier' in install:
            results.append(f"Bundle ID: {install['CFBundleIdentifier']}")

        return results, install_min_os

    def _validate_os_versions(self, minosversions, highest_minosversion, item_min_os):
        """Validate OS version consistency"""
        results = ["\nOS Version Validation:"]

        if not minosversions:
            results.append(
                "ℹ️ No minosversion found in any installs items. "
                "Munki default value will used..."
            )
        else:
            results.append(
                f"Found {len(minosversions)} minosversion(s): {', '.join(minosversions)}"
            )
            results.append(f"Highest minosversion: {highest_minosversion}")

            if item_min_os is None:
                results.append(
                    "❌ Error: No minimum_os_version specified in catalog item"
                )
            elif highest_minosversion != item_min_os:
                results.append(
                    f"❌ Error: Highest minosversion ({highest_minosversion}) "
                    f"does not match\nminimum_os_version ({item_min_os})"
                )
            else:
                results.append(
                    f"✅ Highest minosversion matches minimum_os_version ({item_min_os})"
                )

        return results

    def _compare_versions(self, version1, version2):
        """Compare two version strings"""
        def normalize(v):
            return [int(x) for x in v.split(".")]

        v1 = normalize(version1)
        v2 = normalize(version2)

        for i in range(max(len(v1), len(v2))):
            n1 = v1[i] if i < len(v1) else 0
            n2 = v2[i] if i < len(v2) else 0
            if n1 < n2:
                return -1
            elif n1 > n2:
                return 1
        return 0

    def _get_catalog_items(self, item_name):
        """Get catalog items for a specific item"""
        try:
            catalog_data = self._read_catalog()
            if catalog_data:
                return [item for item in catalog_data if item.get('name') == item_name]
            return []
        except Exception as e:
            logger.error(f"Error getting catalog items: {e}")
            return []
