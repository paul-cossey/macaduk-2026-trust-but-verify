# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Core auto update tester module containing the main AutoUpdateTester class.
"""

import subprocess
import os
import sys
from datetime import datetime
from pathlib import Path
import logging
from typing import Dict, List, Optional
from .config_manager import get_config

# Set up logging
logger = logging.getLogger(__name__)

# Constants for UI messages
BUNDLE_ID_SELECTION_HEADER = "\nBundle ID Selection:"
INVALID_SELECTION_MSG = "❌ Invalid selection"
ENTER_BUNDLE_IDS_PROMPT = "Enter bundle IDs (comma-separated for multiple): "
APP_NAME_LABEL = "App Name"
RESTORING_SECURITY_TOOLS_MSG = "\nRestoring security tool states..."


class AutoUpdateTester:
    """Main class that orchestrates software testing using Munki and security tools."""

    def __init__(self, catalog_name="testing"):
        self.catalog_name = catalog_name
        self.catalog_path = f"/Library/Managed Installs/catalogs/{catalog_name}"
        config = get_config()
        manifest_name = config.get_munki_manifest_name()
        from ..munki.manifest_manager import ManifestManager
        self.manifest_path = ManifestManager.resolve_manifest_path(manifest_name)
        self.report_data = {
            "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_info": {},  # Will be filled later when _get_system_info is available
            "test_results": [],
            "security_events": [],
            "install_details": [],
            "uninstall_results": [],
            "loop_install_test": {},  # Add new section for loop install results
            "loop_uninstall_test": {}  # Add new section for loop uninstall results
        }
        self.initial_notifications = None
        self.initial_sysext = ""
        self.initial_btm = ""
        self.initial_launch_items = set()

        # Import configurations from config module
        from src.core.config import security_tools, event_formatting, report_config
        self.security_tools = security_tools
        self.event_formatting = event_formatting
        self.report_config = report_config

        self.monitoring_processes = {}

    def _get_console_user(self):
        """Get the current console user even when running as root"""
        try:
            # Try stat method first
            current_user = subprocess.check_output(
                ["stat", "-f", "%Su", "/dev/console"],
                text=True
            ).strip()

            if not current_user or current_user == "root":
                # Try scutil method
                scutil_cmd = (
                    "scutil <<< 'show State:/Users/ConsoleUser' | "
                    "awk '/Name :/ { print $3 }'"
                )
                current_user = subprocess.check_output(
                    scutil_cmd,
                    shell=True,
                    text=True
                ).strip()

            return current_user if current_user else "Unknown"

        except Exception as e:
            logger.error(f"Error getting console user: {e}")
            return "Unknown"

    def analyze_and_generate_profiles(self, app_name: str, app_path: str = None) -> List[Dict]:
        """
        Analyze an application and generate configuration profiles.
        This handles the first phase of profile generation.

        Args:
            app_name: Name of the application
            app_path: Optional path to the .app bundle

        Returns:
            List of generated profile information
        """
        logger.info(f"Analyzing application and generating profiles for {app_name}")

        # Find the application if path not provided
        if not app_path:
            app_path = self._find_application_path(app_name)

        if not app_path:
            logger.warning(f"Could not find application path for {app_name}")
            return []

        # Analyze the application
        analysis = self.analyze_application(app_path)

        if not analysis:
            logger.warning(f"Could not analyze application {app_name}")
            return []

        # Generate profiles from analysis
        profiles = self.generate_profiles_from_analysis([analysis])

        if profiles:
            logger.info(f"Generated {len(profiles)} initial profiles for {app_name}")

            # Enhance profiles with system data if available
            if analysis and 'bundle_id' in analysis and 'team_id' in analysis:
                enhanced_profiles, _ = self.enhance_profiles_with_system_data(
                    app_name, analysis['bundle_id'], analysis['team_id']
                )
                if enhanced_profiles:
                    logger.info(f"Enhanced {len(enhanced_profiles)} profiles with system data")
                    profiles.extend(enhanced_profiles)
        else:
            logger.info(f"No configuration profiles needed for {app_name}")

        return profiles

    def enhance_profiles_with_system_data(self, app_name: str, bundle_id: str, team_id: str) -> tuple:
        """
        Enhance profiles with system-level detection using existing captured system data.
        This leverages data already captured by the system checks and comparisons.

        Args:
            app_name: Name of the application
            bundle_id: Application bundle identifier
            team_id: Application team identifier

        Returns:
            Tuple of (updated_profiles, saved_files) where updated_profiles is a list
            of new/updated profile info and saved_files is a list of saved file paths
        """
        logger.info(f"Enhancing profiles with existing system data for {app_name}")

        # Get the system data that's already been captured
        # We want the CURRENT btm data (after installation) to detect new login items
        btm_data = getattr(self, 'current_btm', None)
        initial_launch_items = getattr(self, 'initial_launch_items', set())

        # Debug BTM data availability
        if btm_data:
            logger.info(f"Current BTM data available for profile enhancement (length: {len(btm_data)})")
        else:
            logger.warning("No current BTM data available for profile enhancement")
            # Try to get BTM data from the current state
            try:
                logger.info("Attempting to capture current BTM data for profile enhancement")
                btm_result = subprocess.run(['sfltool', 'dumpbtm'], capture_output=True, text=True, timeout=30)
                if btm_result.returncode == 0 and btm_result.stdout.strip():
                    btm_data = btm_result.stdout.strip()
                    logger.info(f"Successfully captured current BTM data (length: {len(btm_data)})")
                else:
                    logger.warning("Failed to capture current BTM data")
            except Exception as e:
                logger.error(f"Error capturing current BTM data: {e}")

        # Get current launch items (this would be captured during system comparison)
        current_launch_items = getattr(self, 'current_launch_items', set())

        # Update profiles using existing system data
        updated_profiles = self.update_profiles_with_system_data(
            app_name, bundle_id, team_id, btm_data, initial_launch_items, current_launch_items
        )

        if updated_profiles:
            logger.info(f"Enhanced {len(updated_profiles)} profiles with system data")

            # Save ALL generated profiles (not just the new ones) so that
            # merge_managed_login_items_profiles() can merge the initial scan profile
            # with the system-detected enhanced profile into a single file
            saved_files = self.save_profiles()  # Uses self.generated_profiles
            if saved_files:
                logger.info(f"Saved enhanced profiles: {saved_files}")
            return updated_profiles, saved_files or []
        else:
            logger.info(f"No profile enhancements needed for {app_name}")

        return updated_profiles, []

    def _find_application_path(self, app_name: str) -> Optional[str]:
        """
        Find the path to an installed application.

        Args:
            app_name: Name of the application

        Returns:
            Path to the .app bundle or None if not found
        """
        # Common application paths
        search_paths = [
            "/Applications",
            "/System/Applications",
            "/Applications/Utilities",
            os.path.expanduser("~/Applications")
        ]

        # Normalize app name (add .app if not present)
        if not app_name.endswith('.app'):
            app_name += '.app'

        for search_path in search_paths:
            app_path = os.path.join(search_path, app_name)
            if os.path.exists(app_path):
                logger.info(f"Found application at: {app_path}")
                return app_path

        logger.warning(f"Application {app_name} not found in standard locations")
        return None

    def prompt_manual_profile_generation(self, save_location, clean_munki_name):
        """
        Prompt user to manually generate additional configuration profiles.

        Args:
            save_location: Base save location
            clean_munki_name: Cleaned Munki name for folder structure

        Returns:
            List of generated profile information
        """
        print("\n" + "=" * 70)
        print("Manual Configuration Profile Generation")
        print("=" * 70)
        print("Would you like to manually generate additional configuration profiles?")
        print("This is useful when automated scanning couldn't detect all requirements.")

        response = input("\nGenerate manual profiles? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            return []

        # Store munki item name for consistent naming and save location
        self.munki_item_name = clean_munki_name
        self.save_location = save_location

        # Create munki folder if it doesn't exist
        munki_folder = Path(save_location) / clean_munki_name
        from ..utils.file_helpers import FileHelpers
        FileHelpers.create_directory_with_permissions(munki_folder)

        generated_profiles = []

        # Available profile types
        profile_types = {
            '1': {'name': 'PPPC (Privacy Preferences Policy Control)', 'type': 'pppc'},
            '2': {'name': 'Notifications', 'type': 'notifications'},
            '3': {'name': 'System Extensions', 'type': 'system_extensions'},
            '4': {'name': 'Kernel Extensions', 'type': 'kernel_extensions'},
            '5': {'name': 'Screen Recording', 'type': 'screen_recording'},
            '6': {'name': 'Content Filter', 'type': 'content_filter'},
            '7': {'name': 'Managed Login Items', 'type': 'managed_login_items'}
        }

        while True:
            print("\n" + "-" * 50)
            print("Available Profile Types:")
            print("-" * 50)
            for key, value in profile_types.items():
                print(f"{key}. {value['name']}")
            print("q. Quit manual profile generation")

            choice = input("\nSelect profile type to generate (1-7 or q): ").strip().lower()

            if choice == 'q':
                break
            elif choice in profile_types:
                profile_type = profile_types[choice]['type']
                profile_name = profile_types[choice]['name']

                print(f"\n📋 Generating {profile_name} Profile")
                print("-" * 40)

                # Get existing information from previous analyses
                existing_info = self._get_existing_app_info()

                try:
                    profile_data = self._generate_manual_profile(profile_type, existing_info)
                    if profile_data:
                        generated_profiles.extend(profile_data)
                        print(f"✅ Generated {profile_name} profile successfully")
                    else:
                        print(f"⏭️  Skipped {profile_name} profile generation")
                except Exception as e:
                    print(f"❌ Error generating {profile_name} profile: {e}")
                    logger.error(f"Error generating manual {profile_type} profile: {e}")
            else:
                print(f"{INVALID_SELECTION_MSG}. Please choose 1-7 or q.")

        return generated_profiles

    def _get_existing_app_info(self):
        """Get existing app information from previous analyses."""
        existing_info = {
            'bundle_ids': set(),
            'team_ids': set(),
            'app_names': set(),
            'paths': set()
        }

        # Collect from application analyses
        if hasattr(self, 'report_data') and 'application_analyses' in self.report_data:
            for analysis in self.report_data['application_analyses']:
                code_signing = analysis.get('code_signing', {})
                if code_signing.get('bundle_id'):
                    existing_info['bundle_ids'].add(code_signing['bundle_id'])
                if code_signing.get('team_id'):
                    existing_info['team_ids'].add(code_signing['team_id'])
                if analysis.get('app_path'):
                    existing_info['paths'].add(analysis['app_path'])
                    app_name = os.path.basename(analysis['app_path']).replace('.app', '')
                    existing_info['app_names'].add(app_name)

        # Collect from code signing results
        if hasattr(self, 'report_data') and 'code_signing_results' in self.report_data:
            for result in self.report_data['code_signing_results']:
                if result.get('bundle_id'):
                    existing_info['bundle_ids'].add(result['bundle_id'])
                if result.get('team_id'):
                    existing_info['team_ids'].add(result['team_id'])
                if result.get('path'):
                    existing_info['paths'].add(result['path'])
                    app_name = os.path.basename(result['path']).replace('.app', '')
                    existing_info['app_names'].add(app_name)

        return existing_info

    def _generate_manual_profile(self, profile_type, existing_info):
        """Generate a specific type of manual profile."""
        from ..profiles.profile_templates import ProfileTemplates

        templates = ProfileTemplates()

        if profile_type == 'pppc':
            return self._generate_manual_pppc_profile(templates, existing_info)
        elif profile_type == 'notifications':
            return self._generate_manual_notifications_profile(templates, existing_info)
        elif profile_type == 'system_extensions':
            return self._generate_manual_system_extensions_profile(templates, existing_info)
        elif profile_type == 'kernel_extensions':
            return self._generate_manual_kernel_extensions_profile(templates, existing_info)
        elif profile_type == 'screen_recording':
            return self._generate_manual_screen_recording_profile(templates, existing_info)
        elif profile_type == 'content_filter':
            return self._generate_manual_content_filter_profile(templates, existing_info)
        elif profile_type == 'managed_login_items':
            return self._generate_manual_managed_login_items_profile(templates, existing_info)

        return []

    def _generate_manual_pppc_profile(self, templates, existing_info):
        """Generate manual PPPC profile with support for multiple bundle IDs."""
        print("PPPC (Privacy Preferences Policy Control) Profile Generation")
        print("This allows applications to access protected resources without user prompts.")

        # Show existing information
        if existing_info['bundle_ids']:
            print(f"\nExisting Bundle IDs found: {', '.join(existing_info['bundle_ids'])}")
        if existing_info['app_names']:
            print(f"Existing App Names found: {', '.join(existing_info['app_names'])}")
        if existing_info['team_ids']:
            print(f"Existing Team IDs found: {', '.join(existing_info['team_ids'])}")

        # Get bundle IDs
        bundle_ids = self._get_bundle_ids_for_manual_pppc(existing_info)
        if not bundle_ids:
            return []

        # Get team ID
        team_id = self._prompt_with_existing("Team ID (optional, applies to all bundle IDs)", existing_info['team_ids'], "")

        # Get service selection
        pppc_services, service_nums = self._get_pppc_service_selection(bundle_ids)
        if not service_nums:
            return []

        # Build PPPC requirements
        pppc_requirements = self._build_pppc_requirements_from_selection(
            bundle_ids, service_nums, pppc_services, team_id, existing_info
        )
        if not pppc_requirements:
            return []

        # Read existing profile requirements
        existing_pppc_requirements = self._read_existing_pppc_profile_requirements(existing_info)

        # Merge requirements
        all_pppc_requirements = self._merge_pppc_requirements(existing_pppc_requirements, pppc_requirements)

        # Generate and save profile
        profile_display_name = f"PPPC - Allow {self.munki_item_name}"
        profile_data = templates.create_consolidated_pppc_profile(all_pppc_requirements, profile_display_name)
        filename = f"PPPC - Allow {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'PPPC')

    def _get_bundle_ids_for_manual_pppc(self, existing_info):
        """Get bundle IDs for manual PPPC profile with interactive menu or manual entry."""
        print(BUNDLE_ID_SELECTION_HEADER)
        if existing_info['bundle_ids']:
            existing_list = list(existing_info['bundle_ids'])
            print("Available bundle IDs:")
            for i, bid in enumerate(existing_list, 1):
                print(f"  {i}. {bid}")
            print(f"  {len(existing_list) + 1}. Enter manually")

            choice = input(f"Select bundle IDs (numbers comma-separated, e.g., 1,3 or choose {len(existing_list) + 1} for manual): ").strip()

            if choice == str(len(existing_list) + 1):
                # Manual entry
                bundle_ids_input = input(ENTER_BUNDLE_IDS_PROMPT).strip()
            else:
                # Parse selections
                try:
                    selected_indices = [int(x.strip()) - 1 for x in choice.split(',')]
                    selected_bundle_ids = [existing_list[i] for i in selected_indices if 0 <= i < len(existing_list)]
                    bundle_ids_input = ', '.join(selected_bundle_ids)
                except (ValueError, IndexError):
                    print(INVALID_SELECTION_MSG)
                    return []
        else:
            bundle_ids_input = input(ENTER_BUNDLE_IDS_PROMPT).strip()

        if not bundle_ids_input:
            return []

        # Parse bundle IDs
        return [bid.strip() for bid in bundle_ids_input.split(',')]

    def _get_pppc_service_selection(self, bundle_ids):
        """Get PPPC service selection from user."""
        # Define available PPPC services with correct service keys (without kTCCService prefix)
        # Note: Screen Recording, Camera, and Microphone are excluded:
        # - Screen Recording: Handled via separate Screen Recording profile
        # - Camera/Microphone: PPPC can only deny these permissions, not allow (manual only profiles)
        pppc_services = {
            '1': {'service': 'SystemPolicyDocumentsFolder', 'name': 'Documents Folder'},
            '2': {'service': 'SystemPolicyDesktopFolder', 'name': 'Desktop Folder'},
            '3': {'service': 'SystemPolicyDownloadsFolder', 'name': 'Downloads Folder'},
            '4': {'service': 'SystemPolicyNetworkVolumes', 'name': 'Network Volumes'},
            '5': {'service': 'SystemPolicyRemovableVolumes', 'name': 'Removable Volumes'},
            '6': {'service': 'SystemPolicyAllFiles', 'name': 'Full Disk Access'},
            '7': {'service': 'Accessibility', 'name': 'Accessibility'},
            '8': {'service': 'PostEvent', 'name': 'Automation (Send Events)'},
            '9': {'service': 'SystemPolicyAppBundles', 'name': 'Control Other Applications'}
        }

        print(f"\nSelect PPPC services for bundle IDs: {', '.join(bundle_ids)}")
        for key, value in pppc_services.items():
            print(f"{key}. {value['name']}")

        selected_services = input("\nEnter service numbers (comma-separated, e.g., 1,7,9): ").strip()
        if not selected_services:
            return pppc_services, []

        service_nums = [num.strip() for num in selected_services.split(',')]
        return pppc_services, service_nums

    def _build_pppc_requirements_from_selection(self, bundle_ids, service_nums, pppc_services, team_id, existing_info):
        """Build PPPC requirements from user selection."""
        pppc_requirements = []
        try:
            for bundle_id in bundle_ids:
                # Get app name for this bundle ID from existing info or derive from bundle ID
                app_name = None
                if existing_info['app_names']:
                    # Use the first available app name as a fallback
                    app_name = list(existing_info['app_names'])[0]
                else:
                    # Derive app name from bundle ID (last component)
                    app_name = bundle_id.split('.')[-1]

                for num in service_nums:
                    if num in pppc_services:
                        service = pppc_services[num]['service']
                        # Camera and Microphone only support deny (allowed: False)
                        # All other services support allow (allowed: True)
                        allowed = False if service in ['Camera', 'Microphone'] else True

                        pppc_requirements.append({
                            'bundle_id': bundle_id,
                            'team_id': team_id if team_id else None,
                            'service': service,
                            'service_name': pppc_services[num]['name'],
                            'app_name': app_name,  # Add the missing app_name field
                            'allowed': allowed,
                            'code_requirement': f'identifier "{bundle_id}"'
                        })
        except Exception as e:
            print(f"❌ Error parsing service selection: {e}")
            return []

        return pppc_requirements

    def _read_existing_pppc_profile_requirements(self, existing_info):
        """Read and parse existing PPPC profile requirements."""
        existing_profile_path = Path(self.save_location) / self.munki_item_name / f"PPPC - Allow {self.munki_item_name}.mobileconfig"
        existing_pppc_requirements = []

        if not existing_profile_path.exists():
            return existing_pppc_requirements

        try:
            import plistlib
            with open(existing_profile_path, 'rb') as f:
                existing_profile = plistlib.load(f)

            # Extract existing PPPC requirements from the privacy payload
            for payload in existing_profile.get('PayloadContent', []):
                if payload.get('PayloadType') == 'com.apple.TCC.configuration-profile-policy':
                    for service in payload.get('Services', {}):
                        for app_item in payload['Services'][service]:
                            # Extract team ID from code requirement if present
                            extracted_team_id = None
                            code_req = app_item.get('CodeRequirement', '')
                            # Team ID is in certificate leaf[subject.OU] = "TEAMID"
                            if 'certificate leaf[subject.OU]' in code_req:
                                try:
                                    # Extract the team ID from after the = sign
                                    team_part = code_req.split('certificate leaf[subject.OU]')[1]
                                    # Team ID is between = and either end of string or next space/quote
                                    team_part = team_part.split('=')[1].strip()
                                    # Remove quotes and any trailing characters
                                    extracted_team_id = team_part.strip('"').split()[0].strip('"')
                                except (IndexError, AttributeError):
                                    extracted_team_id = None

                            # Get app name from existing info or derive from bundle ID
                            if existing_info['app_names']:
                                app_name = list(existing_info['app_names'])[0]
                            else:
                                app_name = app_item.get('Identifier', '').split('.')[-1]

                            existing_pppc_requirements.append({
                                'bundle_id': app_item.get('Identifier', ''),
                                'service': service,
                                'team_id': extracted_team_id,
                                'allowed': app_item.get('Allowed', True),
                                'code_requirement': code_req,
                                'app_name': app_name
                            })

            print(f"   📋 Found existing PPPC profile with {len(existing_pppc_requirements)} permission(s)")

        except Exception as e:
            print(f"   ⚠️  Could not read existing PPPC profile: {e}")

        return existing_pppc_requirements

    def _merge_pppc_requirements(self, existing_pppc_requirements, pppc_requirements):
        """Merge existing and new PPPC requirements, removing duplicates."""
        all_pppc_requirements = existing_pppc_requirements.copy()
        existing_keys = {(req['bundle_id'], req['service']) for req in existing_pppc_requirements}

        for new_req in pppc_requirements:
            key = (new_req['bundle_id'], new_req['service'])
            if key not in existing_keys:
                all_pppc_requirements.append(new_req)

        if len(all_pppc_requirements) > len(pppc_requirements):
            print(f"   🔄 Merging with existing profile - total permissions: {len(all_pppc_requirements)}")

        return all_pppc_requirements

    def _get_bundle_ids_from_user(self, existing_info):
        """Get bundle IDs from user with support for existing selections.

        Returns:
            list: List of bundle IDs, or empty list if user cancelled
        """
        if existing_info['bundle_ids']:
            existing_list = list(existing_info['bundle_ids'])
            print("Existing bundle ids:")
            for i, bid in enumerate(existing_list, 1):
                print(f"  {i}. {bid}")
            print(f"  {len(existing_list) + 1}. Enter manually")

            choice = input(f"Select bundle id (1-{len(existing_list) + 1}): ").strip()

            if choice == str(len(existing_list) + 1):
                bundle_ids_input = input(ENTER_BUNDLE_IDS_PROMPT).strip()
            else:
                try:
                    selected_index = int(choice) - 1
                    if 0 <= selected_index < len(existing_list):
                        bundle_ids_input = existing_list[selected_index]
                    else:
                        print(INVALID_SELECTION_MSG)
                        return []
                except ValueError:
                    print(INVALID_SELECTION_MSG)
                    return []
        else:
            bundle_ids_input = input(ENTER_BUNDLE_IDS_PROMPT).strip()

        if not bundle_ids_input:
            return []

        return [bid.strip() for bid in bundle_ids_input.split(',')]

    def _read_existing_notifications_profile(self):
        """Read existing notifications profile to get current bundle IDs.

        Returns:
            list: List of existing bundle IDs
        """
        existing_profile_path = Path(self.save_location) / self.munki_item_name / f"Notifications - Allow {self.munki_item_name}.mobileconfig"
        existing_bundle_ids = []

        if not existing_profile_path.exists():
            return existing_bundle_ids

        try:
            import plistlib
            with open(existing_profile_path, 'rb') as f:
                existing_profile = plistlib.load(f)

            for payload in existing_profile.get('PayloadContent', []):
                if payload.get('PayloadType') == 'com.apple.notificationsettings':
                    for app_item in payload.get('NotificationSettings', []):
                        if app_item.get('BundleIdentifier'):
                            existing_bundle_ids.append(app_item['BundleIdentifier'])

            print(f"   📋 Found existing notifications profile with {len(existing_bundle_ids)} bundle IDs")

        except Exception as e:
            print(f"   ⚠️  Could not read existing notifications profile: {e}")

        return existing_bundle_ids

    def _generate_manual_notifications_profile(self, templates, existing_info):
        """Generate manual Notifications profile with support for multiple bundle IDs."""
        print("Notifications Profile Generation")
        print("This pre-authorizes applications to send notifications.")

        # Show existing information
        if existing_info['bundle_ids']:
            print(f"\nExisting Bundle IDs found: {', '.join(existing_info['bundle_ids'])}")

        # Get bundle IDs from user
        print(BUNDLE_ID_SELECTION_HEADER)
        bundle_ids = self._get_bundle_ids_from_user(existing_info)

        if not bundle_ids:
            return []

        # Get app name (will be used for profile display name)
        app_name = self._prompt_with_existing(APP_NAME_LABEL, existing_info['app_names'], bundle_ids[0].split('.')[-1])

        # Read and merge with existing notifications profile
        existing_bundle_ids = self._read_existing_notifications_profile()
        all_bundle_ids = list(set(existing_bundle_ids + bundle_ids))

        if len(all_bundle_ids) > len(bundle_ids):
            print(f"   🔄 Merging with existing profile - total bundle IDs: {len(all_bundle_ids)}")

        # Generate profile with all bundle IDs
        profile_data = templates.create_notifications_profile(app_name, all_bundle_ids)
        filename = f"Notifications - Allow {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'notifications')

    def _generate_manual_system_extensions_profile(self, templates, existing_info):
        """Generate manual System Extensions profile."""
        print("System Extensions Profile Generation")
        print("This allows system extensions to be loaded without user approval.")

        # Show existing information
        if existing_info['team_ids']:
            print(f"\nExisting Team IDs found: {', '.join(existing_info['team_ids'])}")

        team_ids_input = self._prompt_with_existing("Team IDs (comma-separated)", existing_info['team_ids'])
        if not team_ids_input:
            return []

        team_ids = [tid.strip() for tid in team_ids_input.split(',')]
        app_name = self._prompt_with_existing(APP_NAME_LABEL, existing_info['app_names'], "SystemExtensions")

        # Generate profile
        profile_data = templates.create_system_extension_profile(app_name, team_ids)
        # Use consistent naming format like auto-generated profiles: "System Extensions - Allow {name}"
        filename = f"System Extensions - Allow {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'system_extensions')

    def _generate_manual_kernel_extensions_profile(self, templates, existing_info):
        """Generate manual Kernel Extensions profile."""
        print("Kernel Extensions Profile Generation")
        print("This allows kernel extensions to be loaded without user approval.")

        # Show existing information
        if existing_info['team_ids']:
            print(f"\nExisting Team IDs found: {', '.join(existing_info['team_ids'])}")
        if existing_info['bundle_ids']:
            print(f"Existing Bundle IDs found: {', '.join(existing_info['bundle_ids'])}")

        team_ids_input = self._prompt_with_existing("Team IDs (comma-separated)", existing_info['team_ids'])
        if not team_ids_input:
            return []

        team_ids = [tid.strip() for tid in team_ids_input.split(',')]

        bundle_ids_input = input("Bundle IDs (comma-separated, optional): ").strip()
        bundle_ids = [bid.strip() for bid in bundle_ids_input.split(',')] if bundle_ids_input else None

        app_name = self._prompt_with_existing(APP_NAME_LABEL, existing_info['app_names'], "KernelExtensions")

        # Generate profile
        profile_data = templates.create_kernel_extension_profile(app_name, team_ids, bundle_ids)
        # Use munki item name for consistent naming like auto-generated profiles
        filename = f"Kernel Extensions - {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'kernel_extensions')

    def _generate_manual_screen_recording_profile(self, templates, existing_info):
        """Generate manual Screen Recording profile with support for multiple bundle IDs."""
        print("Screen Recording Profile Generation")
        print("This allows applications to record the screen without user prompts.")

        # Show existing information
        if existing_info['bundle_ids']:
            print(f"\nExisting Bundle IDs found: {', '.join(existing_info['bundle_ids'])}")
        if existing_info['team_ids']:
            print(f"Existing Team IDs found: {', '.join(existing_info['team_ids'])}")

        # Get bundle IDs (support comma-separated list like PPPC and notifications)
        print(BUNDLE_ID_SELECTION_HEADER)
        if existing_info['bundle_ids']:
            existing_list = list(existing_info['bundle_ids'])
            print("Existing bundle ids:")
            for i, bid in enumerate(existing_list, 1):
                print(f"  {i}. {bid}")
            print(f"  {len(existing_list) + 1}. Enter manually")

            choice = input(f"Select bundle id (1-{len(existing_list) + 1}): ").strip()

            if choice == str(len(existing_list) + 1):
                # Manual entry - support comma-separated
                bundle_ids_input = input(ENTER_BUNDLE_IDS_PROMPT).strip()
            else:
                # Single selection from existing
                try:
                    selected_index = int(choice) - 1
                    if 0 <= selected_index < len(existing_list):
                        bundle_ids_input = existing_list[selected_index]
                    else:
                        print(INVALID_SELECTION_MSG)
                        return []
                except ValueError:
                    print(INVALID_SELECTION_MSG)
                    return []
        else:
            bundle_ids_input = input(ENTER_BUNDLE_IDS_PROMPT).strip()

        if not bundle_ids_input:
            return []

        # Parse bundle IDs (support comma-separated for multiple apps)
        bundle_ids = [bid.strip() for bid in bundle_ids_input.split(',')]

        team_id = self._prompt_with_existing("Team ID (optional)", existing_info['team_ids'], "")
        app_name = self._prompt_with_existing(APP_NAME_LABEL, existing_info['app_names'], bundle_ids[0].split('.')[-1])

        # Create screen recording requirements for multiple bundle IDs
        screen_recording_requirements = []
        for bundle_id in bundle_ids:
            screen_recording_requirements.append({
                'bundle_id': bundle_id,
                'team_id': team_id if team_id else None,
                'app_name': app_name,
                'code_requirement': f'identifier "{bundle_id}"'
            })

        # Generate consolidated profile
        profile_data = templates.create_consolidated_screen_recording_profile(
            screen_recording_requirements,
            f"Screen Recording - Allow {self.munki_item_name}"
        )
        filename = f"Screen Recording - Allow {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'screen_recording')

    def _generate_manual_content_filter_profile(self, templates, existing_info):
        """Generate manual Content Filter profile."""
        print("Content Filter Profile Generation")
        print("This allows content filter extensions to be used without user approval.")

        # Show existing information
        if existing_info['bundle_ids']:
            print(f"\nExisting Bundle IDs found: {', '.join(existing_info['bundle_ids'])}")
        if existing_info['team_ids']:
            print(f"Existing Team IDs found: {', '.join(existing_info['team_ids'])}")

        bundle_id = self._prompt_with_existing("Bundle ID", existing_info['bundle_ids'])
        if not bundle_id:
            return []

        team_id = self._prompt_with_existing("Team ID", existing_info['team_ids'])
        if not team_id:
            return []

        app_name = self._prompt_with_existing(APP_NAME_LABEL, existing_info['app_names'], bundle_id.split('.')[-1])

        # Generate profile
        profile_data = templates.create_content_filter_profile(app_name, bundle_id, team_id)
        # Use munki item name for consistent naming like auto-generated profiles
        filename = f"Content Filter - {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'content_filter')

    def _generate_manual_managed_login_items_profile(self, templates, existing_info):
        """Generate manual Managed Login Items profile."""
        print("Managed Login Items Profile Generation")
        print("This allows login items to be managed without user interaction.")

        # Show existing information
        if existing_info['bundle_ids']:
            print(f"\nExisting Bundle IDs found: {', '.join(existing_info['bundle_ids'])}")
        if existing_info['team_ids']:
            print(f"Existing Team IDs found: {', '.join(existing_info['team_ids'])}")

        bundle_id = self._prompt_with_existing("Bundle ID", existing_info['bundle_ids'])
        if not bundle_id:
            return []

        team_id = self._prompt_with_existing("Team ID", existing_info['team_ids'])
        if not team_id:
            return []

        app_name = self._prompt_with_existing(APP_NAME_LABEL, existing_info['app_names'], bundle_id.split('.')[-1])

        # Create login item entry
        login_items = [{
            'bundle_id': bundle_id,
            'team_id': team_id,
            'comment': f'Manual entry for {app_name}'
        }]

        # Generate profile
        profile_data = templates.create_managed_login_items_profile(app_name, login_items)
        # Use consistent naming format like auto-generated profiles: "Managed Login Items - Allow {name}"
        filename = f"Managed Login Items - Allow {self.munki_item_name}.mobileconfig"

        return self._save_manual_profile(profile_data, filename, 'managed_login_items')

    def _prompt_with_existing(self, prompt_text, existing_values, default=""):
        """Prompt user with existing values as options."""
        if existing_values:
            existing_list = list(existing_values)
            if len(existing_list) == 1:
                default_value = existing_list[0]
                response = input(f"{prompt_text} (default: {default_value}): ").strip()
                return response if response else default_value
            else:
                print(f"\nExisting {prompt_text.lower()}s:")
                for i, value in enumerate(existing_list, 1):
                    print(f"  {i}. {value}")
                print(f"  {len(existing_list) + 1}. Enter manually")

                choice = input(f"Select {prompt_text.lower()} (1-{len(existing_list) + 1}): ").strip()
                try:
                    choice_idx = int(choice) - 1
                    if 0 <= choice_idx < len(existing_list):
                        return existing_list[choice_idx]
                    elif choice_idx == len(existing_list):
                        return input(f"Enter {prompt_text.lower()}: ").strip()
                except ValueError:
                    pass

        return input(f"{prompt_text}{f' (default: {default})' if default else ''}: ").strip() or default

    def _save_manual_profile(self, profile_data, filename, profile_type):
        """Save a manually generated profile using the same logic as auto-generated profiles."""
        try:
            # Use the same saving logic as the main profile generator
            from ..profiles.profile_generator import ProfileGenerator

            # Create a profile generator with munki_item_name for consistent folder structure
            temp_generator = ProfileGenerator(
                output_directory=str(self.save_location),
                munki_item_name=self.munki_item_name
            )

            # Format the profile data for saving
            profile_info = {
                'type': profile_type,
                'filename': filename,
                'profile': profile_data
            }

            # Save the profile
            saved_files = temp_generator.save_profiles([profile_info])

            if saved_files:
                return [profile_info]
            else:
                print(f"❌ Failed to save {filename}")
                return []

        except Exception as e:
            print(f"❌ Error saving manual profile: {e}")
            logger.error(f"Error saving manual profile {filename}: {e}")
            return []

    def prompt_manual_ea_generation(self, save_location, clean_munki_name):
        """
        Prompt user to generate Extension Attribute for manual installation.

        Args:
            save_location: Base save location
            clean_munki_name: Cleaned Munki name for folder structure

        Returns:
            Path to generated EA script, or None
        """
        from ..profiles.ea_generator import ExtensionAttributeGenerator

        print("\n" + "=" * 70)
        print("Extension Attribute Generation")
        print("=" * 70)
        print("Would you like to generate an Extension Attribute (EA) script?")
        print("This helps track the installed version of the application.")

        response = input("\nGenerate Extension Attribute? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            return None

        # Create munki folder if it doesn't exist
        munki_folder = Path(save_location) / clean_munki_name
        from ..utils.file_helpers import FileHelpers
        FileHelpers.create_directory_with_permissions(munki_folder)

        # Initialize EA generator
        ea_gen = ExtensionAttributeGenerator()

        # Collect available options
        pkg_receipts = self._extract_pkg_receipts_from_analysis()
        app_bundles = self._extract_app_bundles_from_analysis()

        # Present options
        print("\n" + "-" * 50)
        print("Extension Attribute Options:")
        print("-" * 50)

        options = {}
        option_num = 1

        # Add PKG receipt options
        if pkg_receipts:
            print("\nPKG Receipt-Based EA:")
            for pkg in pkg_receipts:
                options[str(option_num)] = {
                    'type': 'receipt',
                    'data': pkg
                }
                print(f"  {option_num}. {pkg['name']} (ID: {pkg['package_id']}, Version: {pkg['version']})")
                option_num += 1

        # Add app bundle options
        if app_bundles:
            print("\nApplication Bundle-Based EA:")
            for app in app_bundles:
                # Offer both CFBundleVersion and CFBundleShortVersionString
                options[str(option_num)] = {
                    'type': 'app_cfbundleshortversion',
                    'data': app
                }
                print(f"  {option_num}. {app['app_name']} - CFBundleShortVersionString")
                option_num += 1

                options[str(option_num)] = {
                    'type': 'app_cfbundleversion',
                    'data': app
                }
                print(f"  {option_num}. {app['app_name']} - CFBundleVersion")
                option_num += 1

        # Add option to drag and drop new app
        options[str(option_num)] = {
            'type': 'drag_drop',
            'data': None
        }
        print(f"\n  {option_num}. Drag and drop a new application")

        print("\n  q. Cancel EA generation")

        # Get user selection
        choice = input(f"\nSelect EA option (1-{option_num} or q): ").strip().lower()

        if choice == 'q':
            return None

        if choice not in options:
            print(INVALID_SELECTION_MSG)
            return None

        selected_option = options[choice]

        # Generate EA based on selection
        ea_script_path = None
        if selected_option['type'] == 'receipt':
            print(f"\n📋 Generating PKG receipt EA for {selected_option['data']['name']}")
            ea_script_path = ea_gen.generate_receipt_ea_script(
                package_id=selected_option['data']['package_id'],
                munki_name=clean_munki_name,
                output_dir=str(munki_folder)
            )

        elif selected_option['type'] == 'app_cfbundleshortversion':
            print(f"\n📋 Generating CFBundleShortVersionString EA for {selected_option['data']['app_name']}")
            ea_script_path = ea_gen.generate_plist_ea_script(
                path=selected_option['data']['app_path'],
                version_key='CFBundleShortVersionString',
                munki_name=clean_munki_name,
                output_dir=str(munki_folder)
            )

        elif selected_option['type'] == 'app_cfbundleversion':
            print(f"\n📋 Generating CFBundleVersion EA for {selected_option['data']['app_name']}")
            ea_script_path = ea_gen.generate_plist_ea_script(
                path=selected_option['data']['app_path'],
                version_key='CFBundleVersion',
                munki_name=clean_munki_name,
                output_dir=str(munki_folder)
            )

        elif selected_option['type'] == 'drag_drop':
            ea_script_path = self._handle_drag_drop_ea(ea_gen, clean_munki_name, str(munki_folder))

        return ea_script_path

    def _extract_pkg_receipts_from_analysis(self):
        """Extract package receipt information from package analysis data."""
        pkg_receipts = []

        if not hasattr(self, 'report_data') or 'package_analysis' not in self.report_data:
            return pkg_receipts

        analysis_results = self.report_data['package_analysis'].get('analysis_results', [])

        for result in analysis_results:
            pkg_info = result.get('package_info', {})
            package_id = pkg_info.get('identifier', '').strip()
            version = pkg_info.get('version', '').strip()
            name = pkg_info.get('name', '').strip()

            if package_id:
                pkg_receipts.append({
                    'package_id': package_id,
                    'version': version,
                    'name': name or os.path.basename(result.get('package_path', 'Unknown'))
                })

            # Also check components for additional package IDs
            for component in result.get('components', []):
                comp_info = component.get('info', {})
                comp_id = comp_info.get('identifier', '').strip()
                comp_version = comp_info.get('version', '').strip()
                comp_name = component.get('name', '').strip()

                if comp_id and comp_id != package_id:  # Avoid duplicates
                    pkg_receipts.append({
                        'package_id': comp_id,
                        'version': comp_version,
                        'name': comp_name or comp_id.split('.')[-1]
                    })

        return pkg_receipts

    def _extract_app_bundles_from_analysis(self):
        """Extract application bundle information from previous analyses."""
        app_bundles = []

        if not hasattr(self, 'report_data'):
            return app_bundles

        # Collect from application analyses
        if 'application_analyses' in self.report_data:
            for analysis in self.report_data['application_analyses']:
                app_path = analysis.get('app_path', '')
                if app_path and os.path.exists(app_path) and app_path.endswith('.app'):
                    app_name = os.path.basename(app_path).replace('.app', '')
                    code_signing = analysis.get('code_signing', {})

                    app_bundles.append({
                        'app_path': app_path,
                        'app_name': app_name,
                        'bundle_id': code_signing.get('bundle_id', ''),
                        'team_id': code_signing.get('team_id', '')
                    })

        # Collect from code signing results (dragged apps)
        if 'code_signing_results' in self.report_data:
            for result in self.report_data['code_signing_results']:
                app_path = result.get('path', '')
                if app_path and os.path.exists(app_path) and app_path.endswith('.app'):
                    app_name = os.path.basename(app_path).replace('.app', '')

                    # Avoid duplicates
                    if not any(app['app_path'] == app_path for app in app_bundles):
                        app_bundles.append({
                            'app_path': app_path,
                            'app_name': app_name,
                            'bundle_id': result.get('bundle_id', ''),
                            'team_id': result.get('team_id', '')
                        })

        return app_bundles

    def _handle_drag_drop_ea(self, ea_gen, clean_munki_name, munki_folder):
        """Handle drag and drop for EA generation."""
        print("\nDrag and drop an application here (or press Enter to cancel):")
        app_path = input().strip()

        # Allow user to cancel
        if not app_path:
            return None

        # Clean up the path - remove quotes and unescape shell-escaped characters
        # macOS terminal escapes special chars like |, &, (, ), etc. with backslashes
        import re
        app_path = app_path.strip('"').strip("'")  # Remove surrounding quotes
        app_path = re.sub(r'\\(.)', r'\1', app_path)  # Remove escape backslashes

        if not os.path.exists(app_path):
            print(f"❌ Error: Application not found at {app_path}")
            return None

        if not app_path.endswith('.app'):
            print(f"❌ Error: Not an application bundle: {app_path}")
            return None

        # Ask which version key to use
        print("\nWhich version key should the EA use?")
        print("1. CFBundleShortVersionString (most common)")
        print("2. CFBundleVersion")

        version_choice = input("Select version key (1 or 2): ").strip()

        if version_choice == '1':
            version_key = 'CFBundleShortVersionString'
        elif version_choice == '2':
            version_key = 'CFBundleVersion'
        else:
            print(INVALID_SELECTION_MSG)
            return None

        app_name = os.path.basename(app_path).replace('.app', '')
        print(f"\n📋 Generating {version_key} EA for {app_name}")

        ea_script_path = ea_gen.generate_plist_ea_script(
            path=app_path,
            version_key=version_key,
            munki_name=clean_munki_name,
            output_dir=munki_folder
        )

        return ea_script_path


def main():
    """Main entry point for the application."""
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)

    print("\n=== InstallAudit ===")

    # Get installation method from config
    config = get_config()
    installation_method = config.get_installation_method()

    print(f"\n📦 Installation Method: {installation_method}")

    # Check if method is supported
    if installation_method == 'munki_standard':
        return main_munki_standard_install()

    # Prompt for log lookback period configuration
    from .config import prompt_log_lookback_period, update_log_lookback_period
    lookback_minutes = prompt_log_lookback_period()
    update_log_lookback_period(lookback_minutes)
    print(f"✅ Log lookback period set to {lookback_minutes} minutes")

    # Branch based on installation method
    if installation_method == 'manual':
        # Manual installation workflow - no Munki operations
        return main_manual_install()
    elif installation_method == 'munki_local':
        # Munki local manifest workflow (current implementation)
        return main_munki_local_install()
    else:
        print(f"\n❌ Unknown installation method: {installation_method}")
        sys.exit(1)


def main_manual_install():
    """Main workflow for manual user-driven installations."""
    print("\n=== Manual Installation Workflow ===")
    print("You will install the application manually while we monitor security events.\n")

    # Import all necessary components
    from ..munki.manual_installer import ManualInstaller
    from ..security.monitoring import SecurityMonitoring
    from ..security.tool_manager import SecurityToolManager
    from ..security.event_processor import SecurityEventProcessor
    from ..system.checks import SystemChecker
    from ..system.comparisons import SystemComparator
    from ..system.notifications import NotificationChecker
    from ..reporting.report_generator import ReportGenerator
    from ..reporting.output_parser import OutputParser
    from ..utils.process_utils import ProcessUtils
    from ..utils.file_helpers import FileHelpers
    from ..profiles.app_analyzer import AppAnalyzer
    from ..profiles.profile_generator import ProfileGenerator

    # Create composite tester for manual install
    class ManualCompositeTester(
        AutoUpdateTester,
        ManualInstaller,
        SecurityMonitoring,
        SecurityToolManager,
        SecurityEventProcessor,
        SystemChecker,
        SystemComparator,
        NotificationChecker,
        ReportGenerator,
        OutputParser,
        ProcessUtils,
        FileHelpers,
        AppAnalyzer,
        ProfileGenerator
    ):
        def __init__(self):
            AutoUpdateTester.__init__(self, catalog_name="manual")
            ManualInstaller.__init__(self)
            SecurityMonitoring.__init__(self)
            SecurityEventProcessor.__init__(self)
            AppAnalyzer.__init__(self)
            ProfileGenerator.__init__(self, output_directory=None, munki_item_name=None)
            ReportGenerator.__init__(self)
            OutputParser.__init__(self)

    # Create tester
    tester = ManualCompositeTester()

    # Get system info
    tester.report_data["system_info"] = tester._get_system_info()

    # Get save location from user
    print("\n=== Output Location Selection ===")
    save_location = tester.get_save_location()
    tester.output_directory = save_location

    try:
        # Run manual installation workflow
        if tester.manual_install_and_test():
            print("\n✅ Manual installation testing completed")
        else:
            print("\n❌ Manual installation testing failed")

        # Note: System state comparison now happens INSIDE manual_install_and_test()
        # BEFORE profile generation, so BTM changes are available for enhancement.
        # Profile enhancement is handled via _enhance_profiles_with_system_data()
        # which uses filtered BTM changes from system_changes.login_items

        # Configuration profile generation
        print("\n\n=== Configuration Profile Generation ===")
        print("Drag and drop applications to analyze for configuration profiles")
        print("(Press Enter without input when done)\n")

        # Get clean munki name from tester (already cleaned in manual_installer.py)
        clean_munki_name = getattr(tester, 'clean_munki_name', 'ManualInstall')

        # Create output folder for this installation
        from pathlib import Path
        output_folder = Path(save_location) / clean_munki_name
        output_folder.mkdir(parents=True, exist_ok=True)

        # Pass the save_location (not output_folder) and clean_munki_name separately
        tester.prompt_manual_profile_generation(save_location, clean_munki_name)

        # Extension Attribute generation
        print("\n\n=== Extension Attribute Generation ===")
        tester.prompt_manual_ea_generation(save_location, clean_munki_name)

        # Display completion message with uninstallation instructions
        print("\n\n✅ Manual installation testing completed successfully")
        print("\n" + "=" * 60)
        print("UNINSTALLATION:")
        print("⚠️  Please manually uninstall the application when testing is complete.")
        print("   No automated uninstallation is performed for manual installs.")
        print("=" * 60)

        # Generate and save report
        print("\nGenerating final report...")
        report = tester.generate_report(f"Manual Installation - {clean_munki_name}")

        # Save report to the output folder
        report_filename = (
            f"install_audit_{clean_munki_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        )
        report_path = output_folder / report_filename

        try:
            with open(report_path, 'w') as f:
                f.write(report)
            print(f"✅ Report saved to: {report_path}")
        except Exception as e:
            print(f"❌ Error saving report: {e}")

        print("\n" + "=" * 60)
        print("Manual Installation Testing Complete!")
        print("=" * 60)

    except KeyboardInterrupt:
        print("\n\nTesting interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error in manual install workflow: {e}", exc_info=True)
        print(f"\n❌ Error: {e}")
        sys.exit(1)


def _reset_munki_manifest():
    """Reset the Munki manifest by deleting it if it exists."""
    config = get_config()
    manifest_name = config.get_munki_manifest_name()
    from ..munki.manifest_manager import ManifestManager
    manifest_path = ManifestManager.resolve_manifest_path(manifest_name)
    try:
        if os.path.exists(manifest_path):
            os.remove(manifest_path)
            print(f"✅ Munki manifest reset: {manifest_path} deleted.")
        else:
            print("ℹ️ Munki manifest not present, no reset needed.")
    except Exception as e:
        print(f"❌ Error resetting Munki manifest: {e}")
        sys.exit(1)


def _setup_tester_and_catalog():
    """Set up the CompositeTester and select catalog.

    Returns:
        tuple: (tester, selected_catalog, save_location)
    """
    # Import all necessary components
    from ..munki.installer import MunkiInstaller
    from ..munki.manual_installer import ManualInstaller
    from ..munki.catalog_manager import CatalogManager
    from ..munki.manifest_manager import ManifestManager
    from ..security.monitoring import SecurityMonitoring
    from ..security.tool_manager import SecurityToolManager
    from ..security.event_processor import SecurityEventProcessor
    from ..system.checks import SystemChecker
    from ..system.comparisons import SystemComparator
    from ..system.notifications import NotificationChecker
    from ..reporting.report_generator import ReportGenerator
    from ..reporting.output_parser import OutputParser
    from ..utils.process_utils import ProcessUtils
    from ..utils.file_helpers import FileHelpers
    from ..profiles.app_analyzer import AppAnalyzer
    from ..profiles.profile_generator import ProfileGenerator

    # Create a composite tester class that inherits from all modules
    class CompositeTester(
        AutoUpdateTester,
        MunkiInstaller,
        ManualInstaller,
        CatalogManager,
        ManifestManager,
        SecurityMonitoring,
        SecurityToolManager,
        SecurityEventProcessor,
        SystemChecker,
        SystemComparator,
        NotificationChecker,
        ReportGenerator,
        OutputParser,
        ProcessUtils,
        FileHelpers,
        AppAnalyzer,
        ProfileGenerator
    ):
        def __init__(self, catalog_name="testing"):
            # Initialize all parent classes with catalog name where applicable
            AutoUpdateTester.__init__(self, catalog_name)
            CatalogManager.__init__(self, catalog_name)
            MunkiInstaller.__init__(self)  # Initialize MunkiInstaller for catalog item tracking
            ManualInstaller.__init__(self)  # Initialize ManualInstaller
            SecurityMonitoring.__init__(self)  # Initialize SecurityMonitoring for DHS VirusTotal flag
            AppAnalyzer.__init__(self)
            # ProfileGenerator needs output_directory and munki_item_name, will be set later
            ProfileGenerator.__init__(self, output_directory=None, munki_item_name=None)
            ReportGenerator.__init__(self)
            OutputParser.__init__(self)

        def save_profiles(self, profiles=None):
            """
            Override save_profiles to inject catalog item before saving.
            """
            # Set the catalog item if available (from MunkiInstaller)
            if hasattr(self, 'current_catalog_item') and self.current_catalog_item:
                ProfileGenerator.set_catalog_item(self, self.current_catalog_item)

            # Call the parent ProfileGenerator save_profiles method
            return ProfileGenerator.save_profiles(self, profiles)

    # First, let's do a preliminary catalog update to populate the catalogs directory
    # We'll use a temporary tester just for this initial update
    print("\nInitial catalog update to discover available catalogs...")
    temp_tester = CompositeTester()
    if not temp_tester._update_catalog():
        print("❌ Error: Unable to perform initial catalog update")
        print("   Continuing with catalog selection anyway...")

    # Now let the user select a catalog
    print("\n=== Catalog Selection ===")
    from ..munki.catalog_manager import CatalogManager
    catalog_selector = CatalogManager()
    selected_catalog = catalog_selector.select_catalog_interactive()

    if selected_catalog is None:
        print("Catalog selection cancelled")
        sys.exit(1)

    # Create the main tester with the selected catalog
    tester = CompositeTester(selected_catalog)

    # Now populate system info after the composite class is fully initialized
    tester.report_data["system_info"] = tester._get_system_info()

    # Get save location from user
    print("\n=== Output Location Selection ===")
    save_location = tester.get_save_location()

    # Update ProfileGenerator with the selected save location
    tester.output_directory = save_location

    return tester, selected_catalog, save_location


def _select_item_from_catalog(tester, selected_catalog):
    """Select an item from the catalog interactively.

    Args:
        tester: The CompositeTester instance
        selected_catalog: Name of the selected catalog

    Returns:
        tuple: (selected_item, item_name, item_version, item_arch, parsed_items)
    """
    # Update the selected catalog
    print(f"\nUpdating {selected_catalog} catalog...")
    if not tester._update_catalog():
        print(f"❌ Error: Unable to update {selected_catalog} catalog")
        sys.exit(1)

    # Read available items from catalog
    print(f"\nReading {selected_catalog} catalog...")
    catalog_data = tester._read_catalog()

    if not catalog_data:
        print(f"❌ Error: Unable to read {selected_catalog} catalog")
        sys.exit(1)

    # Parse and display available items
    parsed_items = tester._parse_catalog_items(catalog_data)
    print(f"✅ Successfully read catalog with {len(parsed_items)} unique items")

    # Sort items alphabetically by name
    parsed_items.sort(key=lambda x: x['name'].lower())

    print(f"\nAvailable items in {selected_catalog} catalog:")
    print("--------------------------------------")
    for idx, item in enumerate(parsed_items, 1):
        name = item['name']
        version = item['version']
        arch = item['architecture']
        print(f"{idx}. {name} {arch} (version: {version})")
    print("--------------------------------------")

    # Get user selection
    try:
        selection = int(input("\nEnter the number of the item to test: ")) - 1
        if selection < 0 or selection >= len(parsed_items):
            raise ValueError("Selection out of range")

        selected_item = parsed_items[selection]
        item_name = selected_item['name']
        item_version = selected_item['version']
        item_arch = selected_item['architecture']

        print(f"\nSelected: {item_name} {item_arch} (version: {item_version})")

        # Add initial selection to report
        tester.report_data['install_details'].append(f"Selected application: {item_name}")
        tester.report_data['install_details'].append(f"Version: {item_version}")
        tester.report_data['install_details'].append(f"Architecture: {item_arch}")

        return selected_item, item_name, item_version, item_arch, parsed_items

    except (ValueError, IndexError) as e:
        print(INVALID_SELECTION_MSG)
        print(f"Error: {str(e)}")
        sys.exit(1)


def _extract_and_generate_enhanced_profiles(tester, app_path, bundle_id, team_id):
    """Extract app info and generate enhanced profiles.

    Args:
        tester: The CompositeTester instance
        app_path: Path to the application (can be None for BTM-only items)
        bundle_id: Bundle identifier (can be None to not filter by bundle_id)
        team_id: Team identifier

    Returns:
        bool: True if profiles were generated successfully
    """
    # Use bundle_id as app name if available, otherwise use team_id
    if app_path:
        actual_app_name = os.path.basename(app_path).replace('.app', '')
    elif bundle_id:
        # Extract a clean name from bundle_id (e.g., "com.veikk.tabletdrivercenter" -> "TabletDriverCenter")
        actual_app_name = bundle_id.split('.')[-1] if bundle_id else 'Unknown'
        # Capitalize first letter for consistency
        actual_app_name = ''.join(word.capitalize() for word in actual_app_name.split('_'))
    elif team_id:
        # Use team_id as name when we don't have bundle_id
        actual_app_name = f"Team-{team_id}"
    else:
        actual_app_name = "Unknown"

    enhanced_profiles, saved_files = tester.enhance_profiles_with_system_data(
        actual_app_name, bundle_id, team_id
    )

    if enhanced_profiles:
        print(f"   ✅ Generated {len(enhanced_profiles)} enhanced profile(s) for {actual_app_name}")
        if saved_files:
            print(f"   📁 Enhanced profiles saved: {saved_files}")
        return True

    return False


def _extract_codesign_info(app_path):
    """Extract bundle ID and team ID from codesign output.

    Args:
        app_path: Path to the application

    Returns:
        tuple: (bundle_id, team_id) or (None, None) on error
    """
    try:
        codesign_result = subprocess.run(
            ['/usr/bin/codesign', '-dv', '--verbose=4', app_path],
            capture_output=True, text=True, timeout=30
        )

        bundle_id = None
        team_id = None

        for line in codesign_result.stderr.split('\n'):
            line = line.strip()
            if 'TeamIdentifier=' in line:
                team_id = line.split('TeamIdentifier=')[1].strip()
            elif 'Identifier=' in line:
                bundle_id = line.split('Identifier=')[1].strip()

        return bundle_id, team_id

    except Exception as e:
        print(f"   ⚠️  Error analyzing {app_path}: {e}")
        return None, None


def _extract_apps_from_btm_changes(login_items):
    """Extract unique apps from BTM login item changes.

    Args:
        login_items: List of login item changes from system comparison

    Returns:
        Dictionary mapping app_name to (bundle_id, team_id, executable_path)
    """
    apps = {}

    for item in login_items:
        # Skip non-dictionary items (e.g., file change strings like "New file: LaunchDaemon: ...")
        if not isinstance(item, dict):
            continue

        # Get identifier - this could be the BTM identifier
        identifier = item.get('identifier', '')
        name = item.get('name', '')

        # Get parsed fields from item data
        team_id = item.get('team_identifier', '')
        executable_path = item.get('executable_path', '')
        bundle_id = None

        # Also check details array as fallback (for backwards compatibility)
        details = item.get('details', [])
        for detail in details:
            if isinstance(detail, str):
                if detail.startswith('Identifier: ') and not identifier:
                    identifier = detail.replace('Identifier: ', '')
                elif detail.startswith('Team Identifier: ') and not team_id:
                    team_id = detail.replace('Team Identifier: ', '')
                elif detail.startswith('Executable Path: ') and not executable_path:
                    executable_path = detail.replace('Executable Path: ', '')

        # For legacy agents, the identifier format is like "8.com.veikk.tabletdrivercenter"
        # Extract the actual bundle ID (remove the "8." prefix)
        if identifier and identifier.count('.') >= 2:
            # Check if it starts with a number prefix like "8.", "16.", etc.
            parts = identifier.split('.', 1)
            if parts[0].isdigit() and len(parts) > 1:
                bundle_id = parts[1]
            else:
                bundle_id = identifier

        # Use the name as the app key
        if name:
            app_name = name
        elif bundle_id:
            app_name = bundle_id
        else:
            app_name = identifier

        if bundle_id and app_name:
            apps[app_name] = (bundle_id, team_id, executable_path)

    return apps


def _find_app_from_executable_path(executable_path):
    """Try to find an app bundle from an executable path.

    Args:
        executable_path: Path to the executable binary

    Returns:
        Path to the .app bundle or None if not found
    """
    if not executable_path:
        return None

    # Walk up the path looking for a .app bundle
    current_path = executable_path
    for _ in range(10):  # Limit depth to prevent infinite loops
        current_path = os.path.dirname(current_path)
        if not current_path or current_path == '/':
            break

        if current_path.endswith('.app') and os.path.exists(current_path):
            return current_path

    return None


def _generate_enhanced_profiles_workflow(tester):
    """Generate enhanced profiles with fallback logic.

    Args:
        tester: The CompositeTester instance
    """
    print("\n\nGenerating enhanced configuration profiles with system data")
    print("=" * 60)

    # Collect unique applications from both sources to avoid duplicates
    unique_apps = {}  # key: bundle_id, value: (app_path, bundle_id, team_id)

    # Collect from application analyses
    if hasattr(tester, 'report_data') and 'application_analyses' in tester.report_data:
        for analysis in tester.report_data['application_analyses']:
            app_path = analysis.get('app_path', '')
            if not (app_path and os.path.exists(app_path)):
                continue

            code_signing = analysis.get('code_signing', {})
            bundle_id = code_signing.get('bundle_id', '')
            team_id = code_signing.get('team_id', '')

            if bundle_id and team_id:
                unique_apps[bundle_id] = (app_path, bundle_id, team_id)

    # Collect from code signing results (dragged apps)
    if hasattr(tester, 'report_data') and 'code_signing_results' in tester.report_data:
        for result in tester.report_data['code_signing_results']:
            app_path = result.get('path', '')
            if not (app_path and os.path.exists(app_path)):
                continue

            # Extract bundle_id and team_id if not already in unique_apps
            bundle_id, team_id = _extract_codesign_info(app_path)
            if bundle_id and team_id and bundle_id not in unique_apps:
                unique_apps[bundle_id] = (app_path, bundle_id, team_id)

    # NEW: Extract apps from BTM changes (consolidate login items by team, even if apps were dragged)
    if hasattr(tester, 'report_data') and 'system_changes' in tester.report_data:
        system_changes = tester.report_data['system_changes']
        login_items = system_changes.get('login_items', [])

        if login_items:
            if not unique_apps:
                print("   📋 No dragged apps found - extracting apps from detected login items...")
            else:
                print("   📋 Checking for additional login items not covered by dragged apps...")

            apps_from_btm = _extract_apps_from_btm_changes(login_items)

            # Group items by team_id to consolidate related apps
            team_groups = {}
            for app_name, (bundle_id, team_id, executable_path) in apps_from_btm.items():
                if team_id:
                    if team_id not in team_groups:
                        team_groups[team_id] = []
                    team_groups[team_id].append((app_name, bundle_id, executable_path))

            # For each team, create one entry that will generate a consolidated profile
            for team_id, apps_list in team_groups.items():
                # Check if this team_id is already covered by a dragged app
                team_already_covered = any(
                    existing_team_id == team_id
                    for _, _, existing_team_id in unique_apps.values()
                )

                if not team_already_covered:
                    # Use the first app as the representative
                    app_name, bundle_id, executable_path = apps_list[0]
                    app_path = _find_app_from_executable_path(executable_path)

                    # For BTM-discovered items, we DON'T want to filter by bundle_id
                    # We want ALL items from this team, so we pass None as bundle_id to disable filtering
                    # Pass None as bundle_id to disable filtering, but keep team_id
                    unique_apps[team_id] = (app_path, None, team_id)
                    app_names = ', '.join([name for name, _, _ in apps_list])
                    print(f"   ✅ Found {len(apps_list)} login item(s) for team {team_id}: {app_names}")

            # Handle items without team_id separately
            items_without_team = [(name, bid, path) for name, (bid, tid, path) in apps_from_btm.items() if not tid]
            if items_without_team:
                for app_name, bundle_id, executable_path in items_without_team:
                    if bundle_id and bundle_id not in unique_apps:
                        app_path = _find_app_from_executable_path(executable_path)
                        unique_apps[bundle_id] = (app_path, bundle_id, None)
                        print(f"   ✅ Found login item without team ID: {app_name} ({bundle_id})")

    # Process unique applications
    if not unique_apps:
        print("   ℹ️  No applications or login items found for enhanced profile generation")
        return

    print(f"   🔍 Processing {len(unique_apps)} unique application(s) for enhanced profiles")

    profiles_generated = False
    for app_path, bundle_id, team_id in unique_apps.values():
        if app_path:
            print(f"   🔍 Analyzing application for enhanced profiles: {app_path}")
        else:
            print(f"   🔍 Generating profile for login item: {bundle_id}")

        if _extract_and_generate_enhanced_profiles(tester, app_path, bundle_id, team_id):
            profiles_generated = True

    if not profiles_generated:
        print("   ℹ️  No enhanced profiles generated - no login items or launch agents detected")


def _generate_ea_and_recipe(tester, item_name, save_location):
    """Generate Extension Attribute.

    Args:
        tester: The CompositeTester instance
        item_name: Name of the Munki item
        save_location: Directory for output files
    """
    if not hasattr(tester, 'current_catalog_item') or not tester.current_catalog_item:
        return

    from ..profiles.ea_generator import ExtensionAttributeGenerator

    # Use the munki folder that was already created or will be created
    clean_munki_name = item_name.replace(' ', '_').replace('.app', '').replace('/', '_').replace('\\', '_')
    munki_folder = Path(save_location) / clean_munki_name
    from ..utils.file_helpers import FileHelpers
    FileHelpers.create_directory_with_permissions(munki_folder)

    # Generate Extension Attribute
    config = get_config()
    if config.is_ea_creation_enabled():
        ea_gen = ExtensionAttributeGenerator()
        ea_result = ea_gen.generate_extension_attribute(
            catalog_item=tester.current_catalog_item,
            munki_name=item_name,
            output_dir=str(munki_folder)
        )

        if ea_result['generated']:
            ea_script_path = ea_result['path']
            print(f"   ✅ Generated Extension Attribute: {os.path.basename(ea_script_path)}")
    else:
        print("   ℹ️  Extension Attribute creation disabled in config - skipping")


def _generate_and_save_final_report(tester, item_name, item_arch, item_version, save_location):
    """Generate and save the final test report.

    Args:
        tester: The CompositeTester instance
        item_name: Name of the Munki item
        item_arch: Architecture of the item
        item_version: Version of the item
        save_location: Directory for output files

    Returns:
        Path: Path to the saved report
    """
    # Generate and save report
    print("\nGenerating final report...")
    report = tester.generate_report(f"{item_name} {item_arch} (version: {item_version})")

    # Create munki folder for organizational purposes
    clean_munki_name = item_name.replace(' ', '_').replace('.app', '').replace('/', '_').replace('\\', '_')
    munki_folder = Path(save_location) / clean_munki_name
    from ..utils.file_helpers import FileHelpers
    FileHelpers.create_directory_with_permissions(munki_folder)

    # Create report filename with item details
    report_filename = (
        f"install_audit_{item_name}_{item_version}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    )
    report_filename = report_filename.replace(' ', '_').replace('(', '').replace(')', '')

    # Save report to munki folder
    report_path = munki_folder / report_filename
    report_path.write_text(report)

    # Set proper permissions on report file
    FileHelpers.set_file_permissions(report_path)

    print(f"✅ Report generated: {report_path.absolute()}")
    print(f"   📁 All files saved to: {munki_folder.absolute()}")

    return report_path



def _run_munki_install_workflow(tester, selected_catalog, save_location):
    """Shared install/test/uninstall workflow used by both Munki methods."""
    try:
        # Select item from catalog
        _, item_name, item_version, item_arch, _ = _select_item_from_catalog(
            tester, selected_catalog
        )

        # Clean munki name for folder creation
        clean_munki_name = item_name.replace(' ', '_').replace('.app', '').replace('/', '_').replace('\\', '_')

        try:
            input(f"\nReady to Install {item_name}? (Press Enter to continue, Ctrl+C to cancel)")

            if tester.install_and_test(item_name):
                tester.report_data["test_results"].append(
                    f"Successfully installed and tested {item_name} (version: {item_version})"
                )
                print(f"\n✅ Installation of {item_name} completed")
                print("  Please verify the application is installed and functions correctly")
            else:
                tester.report_data["test_results"].append(
                    f"Failed to install/test {item_name} (version: {item_version})"
                )
                print(f"\n❌ Installation of {item_name} failed")
                print("  Please check the logs for details")

            # Compare system states before uninstall
            system_changes = tester._compare_system_checks()
            if system_changes is None:
                print("Warning: Unable to compare system states")

            # Generate enhanced profiles with fallback logic
            _generate_enhanced_profiles_workflow(tester)

            # Generate EA and recipe
            _generate_ea_and_recipe(tester, item_name, save_location)

            input(f"\n\nReady to Uninstall {item_name}? (Press Enter to continue, Ctrl+C to cancel)")
            if tester.uninstall_app(item_name):
                tester.report_data["uninstall_results"].append(
                    f"Successfully uninstalled {item_name} (version: {item_version})"
                )
                print(f"\n✅ Uninstallation of {item_name} completed")
                print("  Please verify the application is completely removed")
            else:
                tester.report_data["uninstall_results"].append(
                    f"Failed to uninstall {item_name} (version: {item_version})"
                )
                print(f"\n❌ Uninstallation of {item_name} failed")
                print("  Please check the logs for details")

            # After uninstallation and before report generation, restore security tool states
            print(RESTORING_SECURITY_TOOLS_MSG)
            tester._manage_security_tool_states(action="restore")

            # Store Munki item name for report generation
            tester.report_data['munki_item_name'] = item_name

            # Offer manual profile generation
            manual_profiles = tester.prompt_manual_profile_generation(save_location, clean_munki_name)
            if manual_profiles:
                print(f"   ✅ Generated {len(manual_profiles)} manual profile(s)")

            # Generate and save final report
            _ = _generate_and_save_final_report(
                tester, item_name, item_arch, item_version, save_location
            )

        except KeyboardInterrupt:
            print("\n\nTest cancelled by user")
            # Ensure we restore security tool states even on cancellation
            print(RESTORING_SECURITY_TOOLS_MSG)
            tester._manage_security_tool_states(action="restore")
            tester.stop_security_monitoring()
            sys.exit(1)

    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        # Ensure we restore security tool states even on error
        print(RESTORING_SECURITY_TOOLS_MSG)
        tester._manage_security_tool_states(action="restore")
        sys.exit(1)


def main_munki_standard_install():
    """Main workflow for standard Munki installations.

    Similar to the local manifest flow but operates on an existing manifest
    (typically managed by a Munki server).  The user selects which manifest
    to modify and the script adds the item to ``managed_installs`` /
    ``managed_uninstalls`` just like the local flow.

    It is recommended to keep the server-side manifest empty so that this
    script can control what gets added locally without the server overriding
    it during the next Munki run.
    """
    print("\n=== Munki Standard Manifest Workflow ===\n")

    # Setup tester and catalog
    tester, selected_catalog, save_location = _setup_tester_and_catalog()

    # --- Manifest selection step ---
    print("\n=== Manifest Selection ===")
    manifest_path = tester.select_manifest_interactive()
    if manifest_path is None:
        print("Manifest selection cancelled")
        sys.exit(1)

    # Override the manifest path with the user's selection
    tester.manifest_path = manifest_path

    _run_munki_install_workflow(tester, selected_catalog, save_location)


def main_munki_local_install():
    """Main workflow for Munki local manifest installations."""
    print("\n=== Munki Local Manifest Workflow ===\n")

    # --- Munki manifest reset step ---
    _reset_munki_manifest()

    # Setup tester and catalog
    tester, selected_catalog, save_location = _setup_tester_and_catalog()

    _run_munki_install_workflow(tester, selected_catalog, save_location)


if __name__ == "__main__":
    main()
