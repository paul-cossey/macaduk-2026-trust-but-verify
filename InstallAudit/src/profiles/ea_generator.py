# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Extension Attribute Generator for InstallAudit.

Generates Extension Attribute scripts based on Munki catalog item analysis.
"""

import os
import logging
from datetime import datetime
from ..core.config_manager import get_config

logger = logging.getLogger(__name__)


class ExtensionAttributeGenerator:
    """Generates Extension Attribute scripts."""

    # Constants
    APPLICATIONS_PATH = '/Applications/'

    def __init__(self):
        """Initialize ExtensionAttributeGenerator."""
        # Get current year for license header
        current_year = datetime.now().year

        # Get custom company name from config (no default fallback)
        config = get_config()
        company_name = config.get_ea_custom_header()

        # Check if license header is enabled
        if config.is_ea_license_header_enabled():
            self.license_header = f"""#!/bin/bash

##########################################################################################
#
# Copyright (c) {current_year}, {company_name}.  All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are met:
#               * Redistributions of source code must retain the above copyright
#                 notice, this list of conditions and the following disclaimer.
#               * Redistributions in binary form must reproduce the above copyright
#                 notice, this list of conditions and the following disclaimer in the
#                 documentation and/or other materials provided with the distribution.
#               * Neither the name of the {company_name} nor the
#                 names of its contributors may be used to endorse or promote products
#                 derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY {company_name.upper()} "AS IS" AND ANY
#       EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#       WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#       DISCLAIMED. IN NO EVENT SHALL {company_name.upper()} BE LIABLE FOR ANY
#       DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#       (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#       LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#       ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#       SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
##########################################################################################
"""
        else:
            # No license header when disabled
            self.license_header = "#!/bin/bash"

    def analyze_catalog_item(self, catalog_item):
        """
        Analyze a catalog item to determine if an extension attribute is needed.

        Args:
            catalog_item: Dictionary containing the catalog item data

        Returns:
            dict: Analysis results with 'needed', 'reason', 'options', 'type', and 'details'
        """
        analysis = {
            'needed': False,
            'reason': '',
            'options': [],
            'type': None,
            'details': {}
        }

        installs_array = catalog_item.get('installs', [])
        receipts_array = catalog_item.get('receipts', [])

        # Track if we have valid installs items that can be used directly
        has_valid_installs = False

        # Check each item in installs array
        for idx, install_item in enumerate(installs_array, 1):
            item_type = install_item.get('type', '')
            path = install_item.get('path', '')
            version_key = install_item.get('version_comparison_key', 'CFBundleShortVersionString')

            # Check if this is a valid installs item (CFBundleShortVersionString in /Applications/)
            if (version_key == 'CFBundleShortVersionString'
                    and item_type == 'application'
                    and path.startswith(self.APPLICATIONS_PATH)):
                has_valid_installs = True

            # Rule 1: CFBundleVersion in Applications folder
            if (version_key == 'CFBundleVersion'
                    and item_type == 'application'
                    and path.startswith(self.APPLICATIONS_PATH)):
                analysis['needed'] = True
                analysis['options'].append({
                    'type': 'installs_cfbundleversion',
                    'index': idx,
                    'path': path,
                    'version_key': version_key,
                    'item_type': item_type,
                    'bundle_id': install_item.get('CFBundleIdentifier', 'Unknown'),
                    'name': install_item.get('CFBundleName', os.path.basename(path))
                })

            # Rule 2: Application/Binary/Plugin NOT in Applications folder
            elif not path.startswith(self.APPLICATIONS_PATH):
                if item_type in ['application', 'bundle', 'plugin']:
                    analysis['needed'] = True
                    analysis['options'].append({
                        'type': 'installs_non_applications',
                        'index': idx,
                        'path': path,
                        'version_key': version_key,
                        'item_type': item_type,
                        'bundle_id': install_item.get('CFBundleIdentifier', 'Unknown'),
                        'name': install_item.get('CFBundleName', os.path.basename(path))
                    })

        # Rule 3: Check for pkg receipts ONLY if there are no valid installs items
        # If there's a valid CFBundleShortVersionString installs item in /Applications/,
        # that can be used directly, so no EA needed for receipts
        if receipts_array and not has_valid_installs and not analysis['needed']:
            analysis['needed'] = True
            for idx, receipt in enumerate(receipts_array, 1):
                analysis['options'].append({
                    'type': 'receipt',
                    'index': idx,
                    'package_id': receipt.get('packageid', 'Unknown'),
                    'version': receipt.get('version', 'Unknown'),
                    'name': receipt.get('packageid', 'Unknown').split('.')[-1]
                })

        # Set reason based on findings
        if analysis['needed']:
            if len(analysis['options']) == 1:
                option = analysis['options'][0]
                if option['type'] == 'installs_cfbundleversion':
                    analysis['reason'] = f"Application uses CFBundleVersion for comparison: {option['path']}"
                elif option['type'] == 'installs_non_applications':
                    analysis['reason'] = f"{option['item_type'].capitalize()} not in /Applications: {option['path']}"
                elif option['type'] == 'receipt':
                    analysis['reason'] = f"Package receipt available: {option['package_id']}"
            else:
                analysis['reason'] = f"Multiple options available ({len(analysis['options'])} items)"

        return analysis

    def prompt_user_selection(self, options):
        """
        Prompt user to select which item to use for the extension attribute.

        Args:
            options: List of option dictionaries

        Returns:
            dict: Selected option, or None if cancelled
        """
        print("\n" + "=" * 70)
        print("Multiple items found - Select which to use for Extension Attribute")
        print("=" * 70)

        for idx, option in enumerate(options, 1):
            if option['type'] == 'receipt':
                print(f"{idx}. Package Receipt: {option['package_id']}")
                print(f"   Version: {option['version']}")
            else:
                print(f"{idx}. {option['item_type'].capitalize()}: {option['name']}")
                print(f"   Path: {option['path']}")
                print(f"   Version Key: {option['version_key']}")
            print()

        while True:
            try:
                choice = input("Enter the number of your selection (or 'q' to skip EA generation): ").strip()
                if choice.lower() == 'q':
                    return None

                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(options):
                    return options[choice_idx]
                else:
                    print(f"❌ Please enter a number between 1 and {len(options)}")
            except (ValueError, KeyboardInterrupt):
                print("\n❌ Invalid input")
                return None

    def generate_plist_ea_script(self, path, version_key, munki_name, output_dir):
        """
        Generate an extension attribute script for reading plist values.

        Args:
            path: Path to the Info.plist or bundle
            version_key: Key to read from plist (e.g., CFBundleShortVersionString)
            munki_name: Name of the Munki item
            output_dir: Directory where the EA script should be saved

        Returns:
            str: Path to the generated EA script, or None if generation failed
        """
        try:
            # Determine if path needs Info.plist appended
            if path.endswith('.app') or path.endswith('.plugin') or path.endswith('.vst3') or path.endswith('.aaxplugin'):
                info_plist_path = f"{path}/Contents/Info.plist"
            else:
                info_plist_path = path

            script_content = f"""{self.license_header}#
# DESCRIPTION
# Checks to see if the info.plist exists, and if it does reads in the wanted version key
#
####################################################################################################
#
# CHANGE LOG
# 1.0 - Created
#
####################################################################################################

infoPlistPath="{info_plist_path}"
versionKey="{version_key}"

if [ -f "${{infoPlistPath}}" ]
then
    appVersion=$(/usr/bin/defaults read "${{infoPlistPath}}" "${{versionKey}}")
    /bin/echo "<result>${{appVersion}}</result>"
else
    /bin/echo "<result></result>"
fi
"""

            filename = f"Extension Attribute - {munki_name}.sh"
            output_path = os.path.join(output_dir, filename)

            with open(output_path, 'w') as f:
                f.write(script_content)

            # Set proper permissions and ownership
            from ..utils.file_helpers import FileHelpers
            FileHelpers.set_file_permissions(output_path)  # Full access, allows deletion without password

            logger.info(f"Generated plist EA script: {output_path}")
            print(f"✅ Generated Extension Attribute script: {filename}")

            return output_path

        except Exception as e:
            logger.error(f"Error generating plist EA script: {e}")
            print(f"❌ Error generating Extension Attribute script: {e}")
            return None

    def generate_receipt_ea_script(self, package_id, munki_name, output_dir):
        """
        Generate an extension attribute script for reading pkg receipt versions.

        Args:
            package_id: Package identifier to check
            munki_name: Name of the Munki item
            output_dir: Directory where the EA script should be saved

        Returns:
            str: Path to the generated EA script, or None if generation failed
        """
        try:
            script_content = f"""{self.license_header}#
# DESCRIPTION
# Checks to see if the package receipt exists, and if it does reads the installed version
#
####################################################################################################
#
# CHANGE LOG
# 1.0 - Created
#
####################################################################################################

pkgID="{package_id}"

if /usr/sbin/pkgutil --pkgs | /usr/bin/grep -E "${{pkgID}}"
then
    pkgVersion=$(/usr/sbin/pkgutil --pkg-info-plist "${{pkgID}}" | /usr/bin/plutil -extract pkg-version xml1 - -o - | /usr/bin/xmllint --xpath "//string/text()" -)
    /bin/echo "<result>${{pkgVersion}}</result>"
else
    /bin/echo "<result></result>"
fi
"""

            filename = f"Extension Attribute - {munki_name}.sh"
            output_path = os.path.join(output_dir, filename)

            with open(output_path, 'w') as f:
                f.write(script_content)

            # Set proper permissions and ownership
            from ..utils.file_helpers import FileHelpers
            FileHelpers.set_file_permissions(output_path)  # Full access, allows deletion without password

            logger.info(f"Generated receipt EA script: {output_path}")
            print(f"✅ Generated Extension Attribute script: {filename}")

            return output_path

        except Exception as e:
            logger.error(f"Error generating receipt EA script: {e}")
            print(f"❌ Error generating Extension Attribute script: {e}")
            return None

    def generate_extension_attribute(self, catalog_item, munki_name, output_dir):
        """
        Analyze catalog item and generate extension attribute script if needed.

        Args:
            catalog_item: Dictionary containing the catalog item data
            munki_name: Name of the Munki item
            output_dir: Directory where the EA script should be saved

        Returns:
            dict: Result with 'needed', 'generated', 'path', and 'details'
        """
        result = {
            'needed': False,
            'generated': False,
            'path': None,
            'details': {}
        }

        # Analyze the catalog item
        analysis = self.analyze_catalog_item(catalog_item)
        result['needed'] = analysis['needed']
        result['details'] = analysis

        if not analysis['needed']:
            logger.info(f"No extension attribute needed for {munki_name}")
            return result

        # Determine which option to use
        selected_option = None
        if len(analysis['options']) == 1:
            selected_option = analysis['options'][0]
            print(f"\n📋 Extension Attribute required: {analysis['reason']}")
        else:
            selected_option = self.prompt_user_selection(analysis['options'])
            if selected_option is None:
                print("⏭️  Skipping Extension Attribute generation")
                return result

        # Generate the appropriate EA script
        if selected_option['type'] == 'receipt':
            ea_path = self.generate_receipt_ea_script(
                selected_option['package_id'],
                munki_name,
                output_dir
            )
        else:
            ea_path = self.generate_plist_ea_script(
                selected_option['path'],
                selected_option['version_key'],
                munki_name,
                output_dir
            )

        if ea_path:
            result['generated'] = True
            result['path'] = ea_path
            result['details']['selected_option'] = selected_option

        return result
