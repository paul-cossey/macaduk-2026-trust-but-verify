# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Configuration Profile Generator.

This module generates configuration profiles based on application analysis results
using the templates defined in profile_templates.py.
"""

import os
import plistlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from .profile_templates import ProfileTemplates
from .ea_generator import ExtensionAttributeGenerator

logger = logging.getLogger(__name__)


class ProfileGenerator:
    """Generates configuration profiles based on application analysis."""

    # Constants
    MANAGED_LOGIN_ITEMS = 'Managed Login Items'
    SERVICE_MANAGEMENT_PAYLOAD_TYPE = 'com.apple.servicemanagement'

    def __init__(self, output_directory: str = None, munki_item_name: str = None):
        """
        Initialize the ProfileGenerator.

        Args:
            output_directory: Directory to save generated profiles
            munki_item_name: Name of the Munki item (used for creating profile folder)
        """
        self.output_directory = output_directory or os.getcwd()
        self.munki_item_name = munki_item_name
        self.templates = ProfileTemplates()
        self.generated_profiles = []
        self.catalog_item = None  # Store catalog item for EA generation

    def set_catalog_item(self, catalog_item: Dict):
        """
        Set the catalog item data for EA generation.

        Args:
            catalog_item: Dictionary containing the catalog item data
        """
        self.catalog_item = catalog_item
        logger.debug(f"Catalog item set for {self.munki_item_name}")

    def generate_profiles_from_analysis(self, application_analyses: List[Dict], security_events: Optional[List[Dict]] = None) -> List[Dict]:
        """Generate consolidated configuration profiles from application analyses and security events."""
        if not application_analyses:
            return []

        # Collect all requirements across all applications
        (
            consolidated_pppc,
            consolidated_screen_recording,
            consolidated_notifications,
            consolidated_system_extensions,
            consolidated_kernel_extensions,
            consolidated_content_filter,
            consolidated_login_items,
            non_manageable_permissions
        ) = self._collect_requirements_from_analyses(application_analyses)

        # Process security events for login items
        if security_events:
            security_login_items = self._process_security_events_for_login_items(security_events)
            consolidated_login_items.extend(security_login_items)

        # Generate consolidated profiles
        generated_profiles = []

        # Generate each profile type
        self._generate_pppc_profile(consolidated_pppc, non_manageable_permissions, generated_profiles)
        self._generate_screen_recording_profile(consolidated_screen_recording, generated_profiles)
        self._generate_notifications_profile(consolidated_notifications, generated_profiles)
        self._generate_login_items_profile(consolidated_login_items, generated_profiles)
        self._generate_system_extensions_profile(consolidated_system_extensions, generated_profiles)
        self._generate_kernel_extensions_profile(consolidated_kernel_extensions, generated_profiles)
        self._generate_content_filter_profile(consolidated_content_filter, generated_profiles)

        self.generated_profiles = generated_profiles
        return generated_profiles

    def _collect_requirements_from_analyses(self, application_analyses: List[Dict]):
        """Collect all requirements across all applications."""
        consolidated_pppc = []
        consolidated_screen_recording = []
        consolidated_notifications = []
        consolidated_system_extensions = []
        consolidated_kernel_extensions = []
        consolidated_content_filter = []
        consolidated_login_items = []

        # Track non-manageable permissions for warnings
        non_manageable_permissions = {
            'bluetooth': [],
            'camera': [],
            'microphone': [],
            'location': [],
            'apple_events_receiver_unknown': []
        }

        # Process each application analysis
        for analysis in application_analyses:
            app_name = analysis.get('app_name', 'Unknown')
            required_profiles = analysis.get('required_profiles', {})
            bundle_id = analysis.get('code_signing', {}).get('bundle_id', '')
            team_id = analysis.get('code_signing', {}).get('team_id', '')

            # Collect PPPC requirements
            if required_profiles.get('pppc'):
                pppc_results, non_manageable_permissions = self._process_pppc_requirements(
                    app_name, bundle_id, team_id,
                    required_profiles['pppc'],
                    non_manageable_permissions
                )
                consolidated_pppc.extend(pppc_results)

            # Collect Screen Recording requirements
            if required_profiles.get('screen_recording'):
                consolidated_screen_recording.append({
                    'app_name': app_name,
                    'bundle_id': bundle_id,
                    'team_id': team_id
                })

            # Collect other profile types
            if required_profiles.get('notifications'):
                consolidated_notifications.append({
                    'app_name': app_name,
                    'bundle_id': bundle_id,
                    'team_id': team_id
                })

            if required_profiles.get('system_extensions'):
                consolidated_system_extensions.extend([{
                    'app_name': app_name,
                    'team_id': ext.get('team_id', team_id),
                    'extension_data': ext,
                    'extension_bundles': required_profiles.get('system_extension_bundles', [])
                } for ext in required_profiles['system_extensions']])

            if required_profiles.get('kernel_extensions'):
                consolidated_kernel_extensions.extend([{
                    'app_name': app_name,
                    'team_id': kext.get('team_id', team_id),
                    'extension_data': kext
                } for kext in required_profiles['kernel_extensions']])

            if required_profiles.get('content_filter'):
                consolidated_content_filter.append({
                    'app_name': app_name,
                    'bundle_id': bundle_id,
                    'team_id': team_id,
                    'extensions': required_profiles.get('content_filter_extensions', [])
                })

            if required_profiles.get('managed_login_items'):
                consolidated_login_items.extend([{
                    'app_name': app_name,
                    'item_data': item
                } for item in required_profiles['managed_login_items']])

        return (
            consolidated_pppc,
            consolidated_screen_recording,
            consolidated_notifications,
            consolidated_system_extensions,
            consolidated_kernel_extensions,
            consolidated_content_filter,
            consolidated_login_items,
            non_manageable_permissions
        )

    def _process_pppc_requirements(
        self, app_name: str, bundle_id: str, team_id: str,
        pppc_reqs: List[Dict], non_manageable_permissions: Dict
    ) -> Tuple[List[Dict], Dict]:
        """Process PPPC requirements and track non-manageable permissions.

        Args:
            app_name: Name of the application
            bundle_id: Bundle identifier of the application
            team_id: Team identifier of the application
            pppc_reqs: List of PPPC requirements to process
            non_manageable_permissions: Dictionary tracking non-manageable permissions

        Returns:
            Tuple of (consolidated_pppc list, updated non_manageable_permissions dict)
        """
        consolidated_pppc = []

        for pppc_req in pppc_reqs:
            # Check for non-manageable permissions and add to warnings
            service = pppc_req.get('service', '')
            if 'bluetooth' in service.lower():
                non_manageable_permissions['bluetooth'].append(app_name)
                continue  # Bluetooth is not a valid TCC/PPPC service
            elif 'camera' in service.lower():
                non_manageable_permissions['camera'].append(app_name)
                continue  # Skip adding to PPPC profile
            elif 'microphone' in service.lower():
                non_manageable_permissions['microphone'].append(app_name)
                continue  # Skip adding to PPPC profile
            elif 'location' in service.lower():
                non_manageable_permissions['location'].append(app_name)
                continue  # Location is not a valid TCC/PPPC service
            elif service == 'AppleEvents' and not pppc_req.get('ae_receiver_bundle_id'):
                # AppleEvents without receiver - add to warnings instead of profile
                non_manageable_permissions['apple_events_receiver_unknown'].append(app_name)
                continue  # Skip adding to PPPC profile

            # Add manageable PPPC requirement
            consolidated_pppc.append({
                'app_name': app_name,
                'service': pppc_req['service'],
                'bundle_id': bundle_id,
                'team_id': team_id,
                'ae_receiver_bundle_id': pppc_req.get('ae_receiver_bundle_id'),
                'ae_receiver_team_id': pppc_req.get('ae_receiver_team_id')
            })

        return consolidated_pppc, non_manageable_permissions

    def _process_security_events_for_login_items(self, security_events: List[Dict]) -> List[Dict]:
        """Process security events and extract BlockBlock daemon events as managed login items."""
        login_items = []

        # --- Patch: Add BlockBlock daemon events as managed login items ---
        for event in security_events:
            if event.get('tool') == 'BlockBlock':
                details = event.get('event', {}).get('details', {})
                # Add if it's a launch daemon or agent
                if details.get('action') == 'allowed' and details.get('path', '').endswith('.plist'):
                    path = details.get('path', '')
                    if path.startswith('/Library/LaunchDaemons'):
                        item_type = 'blockblock_launch_daemon'
                    elif path.startswith('/Library/LaunchAgents'):
                        item_type = 'blockblock_launch_agent'
                    else:
                        item_type = 'blockblock_launch_item'
                    item_data = {
                        'entitlement': item_type,
                        'bundle_id': '',
                        'team_id': '',
                        'plist_path': path,
                        'binary_name': details.get('binary_name'),
                        'binary_path': details.get('binary_path'),
                        'timestamp': details.get('timestamp')
                    }
                    login_items.append({
                        'app_name': details.get('binary_name', 'Unknown'),
                        'item_data': item_data
                    })

        return login_items

    def _generate_pppc_profile(self, consolidated_pppc: List[Dict], non_manageable_permissions: Dict, generated_profiles: List[Dict]):
        """Generate consolidated PPPC profile."""
        if consolidated_pppc:
            try:
                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"PPPC - Allow {clean_name}"
                    filename = f"PPPC - Allow {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = "PPPC - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_pppc_profile(consolidated_pppc, display_name)
                generated_profiles.append({
                    'type': 'PPPC',
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in consolidated_pppc],
                    'non_manageable_warnings': non_manageable_permissions
                })
                logger.info(f"Generated consolidated PPPC profile for {len(set(req['app_name'] for req in consolidated_pppc))} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated PPPC profile: {e}")

    def _generate_screen_recording_profile(self, consolidated_screen_recording: List[Dict], generated_profiles: List[Dict]):
        """Generate consolidated Screen Recording profile."""
        if consolidated_screen_recording:
            try:
                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"Screen Recording - Allow {clean_name}"
                    filename = f"Screen Recording - Allow {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = "Screen Recording - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_screen_recording_profile(consolidated_screen_recording, display_name)
                generated_profiles.append({
                    'type': 'Screen Recording',
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in consolidated_screen_recording]
                })
                logger.info(f"Generated consolidated Screen Recording profile for {len(consolidated_screen_recording)} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated Screen Recording profile: {e}")

    def _generate_notifications_profile(self, consolidated_notifications: List[Dict], generated_profiles: List[Dict]):
        """Generate consolidated Notifications profile."""
        if consolidated_notifications:
            try:
                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"Notifications - Allow {clean_name}"
                    filename = f"Notifications - Allow {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = "Notifications - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_notifications_profile(consolidated_notifications, display_name)
                generated_profiles.append({
                    'type': 'Notifications',
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in consolidated_notifications]
                })
                logger.info(f"Generated consolidated Notifications profile for {len(consolidated_notifications)} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated Notifications profile: {e}")

    def _generate_login_items_profile(self, consolidated_login_items: List[Dict], generated_profiles: List[Dict]):
        """Generate consolidated Managed Login Items profile."""
        if consolidated_login_items:
            try:
                # Transform consolidated_login_items to the format expected by template
                login_items_requirements = []
                for item_group in consolidated_login_items:
                    app_name = item_group['app_name']
                    item_data = item_group['item_data']

                    login_items_requirements.append({
                        'app_name': app_name,
                        'bundle_id': item_data.get('bundle_id', ''),
                        'team_id': item_data.get('team_id', '')
                    })

                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"{self.MANAGED_LOGIN_ITEMS} - Allow {clean_name}"
                    filename = f"{self.MANAGED_LOGIN_ITEMS} - Allow {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = f"{self.MANAGED_LOGIN_ITEMS} - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_managed_login_items_profile(login_items_requirements, display_name)
                generated_profiles.append({
                    'type': self.MANAGED_LOGIN_ITEMS,
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in login_items_requirements]
                })
                logger.info(f"Generated consolidated {self.MANAGED_LOGIN_ITEMS} profile for {len(set(req['app_name'] for req in login_items_requirements))} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated {self.MANAGED_LOGIN_ITEMS} profile: {e}")

    def _generate_system_extensions_profile(self, consolidated_system_extensions: List[Dict], generated_profiles: List[Dict]):
        """Generate consolidated System Extensions profile."""
        if consolidated_system_extensions:
            try:
                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"System Extension - Allow {clean_name}"
                    filename = f"System Extension - Allow {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = "System Extension - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_system_extension_profile(consolidated_system_extensions, display_name)
                generated_profiles.append({
                    'type': 'System Extensions',
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in consolidated_system_extensions]
                })
                logger.info(f"Generated consolidated System Extension profile for {len(set(req['app_name'] for req in consolidated_system_extensions))} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated System Extension profile: {e}")

    def _generate_kernel_extensions_profile(self, consolidated_kernel_extensions: List[Dict], generated_profiles: List[Dict]):
        """Generate consolidated Kernel Extensions profile."""
        if consolidated_kernel_extensions:
            try:
                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"Kernel Extension - {clean_name}"
                    filename = f"Kernel Extension - {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = "Kernel Extension - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_kernel_extension_profile(consolidated_kernel_extensions, display_name)
                generated_profiles.append({
                    'type': 'Kernel Extensions',
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in consolidated_kernel_extensions]
                })
                logger.info(f"Generated consolidated Kernel Extension profile for {len(set(req['app_name'] for req in consolidated_kernel_extensions))} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated Kernel Extension profile: {e}")

    def _generate_content_filter_profile(self, consolidated_content_filter: List[Dict], generated_profiles: List[Dict]):
        """Generate consolidated Content Filter profile."""
        if consolidated_content_filter:
            try:
                # Use munki item name if available, otherwise use generic name
                if self.munki_item_name:
                    clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
                    display_name = f"Content Filter - {clean_name}"
                    filename = f"Content Filter - {clean_name}.mobileconfig"
                else:
                    display_name = None  # Let template generate default name
                    filename = "Content Filter - Consolidated Applications.mobileconfig"

                profile = self.templates.create_consolidated_content_filter_profile(consolidated_content_filter, display_name)
                generated_profiles.append({
                    'type': 'Content Filter',
                    'filename': filename,
                    'profile': profile,
                    'apps': [req['app_name'] for req in consolidated_content_filter]
                })
                logger.info(f"Generated consolidated Content Filter profile for {len(consolidated_content_filter)} applications")
            except Exception as e:
                logger.error(f"Error generating consolidated Content Filter profile: {e}")

    def _generate_profiles_for_app(self, app_name: str, analysis: Dict, required_profiles: Dict) -> List[Dict]:
        """Generate all required profiles for a specific application."""
        generated = []
        bundle_id = analysis.get('code_signing', {}).get('bundle_id', '')
        team_id = analysis.get('code_signing', {}).get('team_id', '')

        # Generate each profile type using dedicated helper methods
        profile = self._generate_pppc_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('pppc'))
        if profile:
            generated.append(profile)

        profile = self._generate_notifications_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('notifications'))
        if profile:
            generated.append(profile)

        profile = self._generate_system_extension_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('system_extensions'))
        if profile:
            generated.append(profile)

        profile = self._generate_kernel_extension_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('kernel_extensions'))
        if profile:
            generated.append(profile)

        profile = self._generate_screen_recording_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('screen_recording'))
        if profile:
            generated.append(profile)

        profile = self._generate_content_filter_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('content_filter'))
        if profile:
            generated.append(profile)

        profile = self._generate_login_items_profile_for_app(app_name, bundle_id, team_id, required_profiles.get('managed_login_items'))
        if profile:
            generated.append(profile)

        return generated

    def _generate_pppc_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, pppc_requirements) -> Optional[Dict]:
        """Generate PPPC profile for a specific application."""
        if not pppc_requirements:
            return None

        try:
            # Format requirements for consolidated method
            pppc_data = []
            for req in pppc_requirements:
                pppc_data.append({
                    'app_name': app_name,
                    'service': req['service'],
                    'bundle_id': bundle_id,
                    'team_id': team_id,
                    'ae_receiver_bundle_id': req.get('ae_receiver_bundle_id'),
                    'ae_receiver_team_id': req.get('ae_receiver_team_id')
                })

            profile = self.templates.create_consolidated_pppc_profile(
                pppc_data,
                f"PPPC - Allow {app_name}"
            )
            filename = f"PPPC - Allow {app_name}.mobileconfig"
            logger.info(f"Generated PPPC profile for {app_name}")
            return {
                'type': 'PPPC',
                'filename': filename,
                'profile': profile,
                'app_name': app_name
            }
        except Exception as e:
            logger.error(f"Error generating PPPC profile for {app_name}: {e}")
            return None

    def _generate_notifications_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, notifications_requirements) -> Optional[Dict]:
        """Generate Notifications profile for a specific application."""
        if not notifications_requirements or not bundle_id:
            return None

        try:
            notifications_data = [{
                'app_name': app_name,
                'bundle_id': bundle_id,
                'team_id': team_id
            }]

            profile = self.templates.create_consolidated_notifications_profile(
                notifications_data,
                f"Notifications - Allow {app_name}"
            )
            filename = f"Notifications - Allow {app_name}.mobileconfig"
            logger.info(f"Generated Notifications profile for {app_name}")
            return {
                'type': 'Notifications',
                'filename': filename,
                'profile': profile,
                'app_name': app_name
            }
        except Exception as e:
            logger.error(f"Error generating Notifications profile for {app_name}: {e}")
            return None

    def _generate_system_extension_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, system_extensions_requirements) -> Optional[Dict]:
        """Generate System Extension profile for a specific application."""
        if not system_extensions_requirements or not team_id:
            return None

        try:
            system_ext_data = []
            for ext in system_extensions_requirements:
                system_ext_data.append({
                    'app_name': app_name,
                    'bundle_id': bundle_id,
                    'team_id': ext.get('team_id', team_id)
                })

            if system_ext_data:
                profile = self.templates.create_consolidated_system_extension_profile(
                    system_ext_data,
                    f"System Extension - Allow {app_name}"
                )
                filename = f"System Extension - Allow {app_name}.mobileconfig"
                logger.info(f"Generated System Extension profile for {app_name}")
                return {
                    'type': 'System Extensions',
                    'filename': filename,
                    'profile': profile,
                    'app_name': app_name
                }
        except Exception as e:
            logger.error(f"Error generating System Extension profile for {app_name}: {e}")
        return None

    def _generate_kernel_extension_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, kernel_extensions_requirements) -> Optional[Dict]:
        """Generate Kernel Extension profile for a specific application."""
        if not kernel_extensions_requirements or not team_id:
            return None

        try:
            kernel_ext_data = []
            for kext in kernel_extensions_requirements:
                kernel_ext_data.append({
                    'app_name': app_name,
                    'bundle_id': bundle_id,
                    'team_id': kext.get('team_id', team_id)
                })

            if kernel_ext_data:
                profile = self.templates.create_consolidated_kernel_extension_profile(
                    kernel_ext_data,
                    f"Kernel Extension - {app_name}"
                )
                filename = f"Kernel Extension - {app_name}.mobileconfig"
                logger.info(f"Generated Kernel Extension profile for {app_name}")
                return {
                    'type': 'Kernel Extensions',
                    'filename': filename,
                    'profile': profile,
                    'app_name': app_name
                }
        except Exception as e:
            logger.error(f"Error generating Kernel Extension profile for {app_name}: {e}")
        return None

    def _generate_screen_recording_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, screen_recording_requirements) -> Optional[Dict]:
        """Generate Screen Recording profile for a specific application."""
        if not screen_recording_requirements or not bundle_id:
            return None

        try:
            screen_recording_data = [{
                'app_name': app_name,
                'bundle_id': bundle_id,
                'team_id': team_id
            }]

            profile = self.templates.create_consolidated_screen_recording_profile(
                screen_recording_data,
                f"Screen Recording - Allow {app_name}"
            )
            filename = f"Screen Recording - Allow {app_name}.mobileconfig"
            logger.info(f"Generated Screen Recording profile for {app_name}")
            return {
                'type': 'Screen Recording',
                'filename': filename,
                'profile': profile,
                'app_name': app_name
            }
        except Exception as e:
            logger.error(f"Error generating Screen Recording profile for {app_name}: {e}")
            return None

    def _generate_content_filter_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, content_filter_requirements) -> Optional[Dict]:
        """Generate Content Filter profile for a specific application."""
        if not content_filter_requirements or not bundle_id or not team_id:
            return None

        try:
            content_filter_data = [{
                'app_name': app_name,
                'bundle_id': bundle_id,
                'team_id': team_id
            }]

            profile = self.templates.create_consolidated_content_filter_profile(
                content_filter_data,
                f"Content Filter - {app_name}"
            )
            filename = f"Content Filter - {app_name}.mobileconfig"
            logger.info(f"Generated Content Filter profile for {app_name}")
            return {
                'type': 'Content Filter',
                'filename': filename,
                'profile': profile,
                'app_name': app_name
            }
        except Exception as e:
            logger.error(f"Error generating Content Filter profile for {app_name}: {e}")
            return None

    def _generate_login_items_profile_for_app(self, app_name: str, bundle_id: str, team_id: str, login_items_requirements) -> Optional[Dict]:
        """Generate Managed Login Items profile for a specific application."""
        if not login_items_requirements:
            return None

        try:
            login_items_data = []
            for item in login_items_requirements:
                login_items_data.append({
                    'app_name': app_name,
                    'bundle_id': item.get('bundle_id', bundle_id),
                    'team_id': item.get('team_id', team_id),
                    'entitlement': item.get('entitlement', '')
                })

            profile = self.templates.create_consolidated_managed_login_items_profile(
                login_items_data,
                f"{self.MANAGED_LOGIN_ITEMS} - Allow {app_name}"
            )
            filename = f"{self.MANAGED_LOGIN_ITEMS} - Allow {app_name}.mobileconfig"
            logger.info(f"Generated {self.MANAGED_LOGIN_ITEMS} profile for {app_name}")
            return {
                'type': self.MANAGED_LOGIN_ITEMS,
                'filename': filename,
                'profile': profile,
                'app_name': app_name
            }
        except Exception as e:
            logger.error(f"Error generating {self.MANAGED_LOGIN_ITEMS} profile for {app_name}: {e}")
            return None

    def merge_managed_login_items_profiles(self, profiles: List[Dict]) -> List[Dict]:
        """
        Merge duplicate Managed Login Items profiles into a single profile.
        If multiple profiles exist for the same app/munki item, merge their rules
        and use the munki item name for the filename.

        Args:
            profiles: List of profile dictionaries

        Returns:
            List of profiles with Managed Login Items merged
        """
        # Separate Managed Login Items profiles from others
        login_items_profiles = [p for p in profiles if p.get('type') == self.MANAGED_LOGIN_ITEMS]
        other_profiles = [p for p in profiles if p.get('type') != self.MANAGED_LOGIN_ITEMS]

        if len(login_items_profiles) <= 1:
            # No merging needed
            return profiles

        logger.info(f"Merging {len(login_items_profiles)} {self.MANAGED_LOGIN_ITEMS} profiles")
        print(f"   🔄 Merging {len(login_items_profiles)} {self.MANAGED_LOGIN_ITEMS} profiles into one...")

        # Collect all unique rules from all profiles
        all_rules = self._collect_unique_login_item_rules(login_items_profiles)

        logger.info(f"Merged {len(all_rules)} unique rules from {len(login_items_profiles)} profiles")
        print(f"   ✅ Merged into {len(all_rules)} unique rules")

        # Create merged profile dict
        merged_profile_dict = self._create_merged_login_items_profile(
            all_rules, login_items_profiles
        )

        # Return other profiles plus the merged one
        return other_profiles + [merged_profile_dict]

    def _collect_unique_login_item_rules(self, login_items_profiles: List[Dict]) -> List[Dict]:
        """Collect all unique rules from login items profiles."""
        all_rules = []
        seen_rule_keys = set()  # Track unique rules by (RuleType, RuleValue, TeamIdentifier)

        for profile_dict in login_items_profiles:
            profile = profile_dict.get('profile', {})
            payload_content = profile.get('PayloadContent', [])

            for payload in payload_content:
                if payload.get('PayloadType') == self.SERVICE_MANAGEMENT_PAYLOAD_TYPE:
                    rules = payload.get('Rules', [])

                    for rule in rules:
                        rule_key = (
                            rule.get('RuleType', ''),
                            rule.get('RuleValue', ''),
                            rule.get('TeamIdentifier', '')
                        )

                        # Only add if we haven't seen this exact rule before
                        if rule_key not in seen_rule_keys:
                            all_rules.append(rule)
                            seen_rule_keys.add(rule_key)

        return all_rules

    def _create_merged_login_items_profile(self, all_rules: List[Dict], login_items_profiles: List[Dict]) -> Dict:
        """Create a merged login items profile from collected rules."""
        # Use munki item name for the merged profile
        if self.munki_item_name:
            clean_name = self.munki_item_name.replace('.app', '').replace(' ', '_').replace('/', '_').replace('\\', '_')
            display_name = f"{self.MANAGED_LOGIN_ITEMS} - Allow {clean_name}"
            filename = f"{self.MANAGED_LOGIN_ITEMS} - Allow {clean_name}.mobileconfig"
        else:
            # Fallback to first profile's app name
            app_name = login_items_profiles[0].get('app_name', 'Application')
            display_name = f"{self.MANAGED_LOGIN_ITEMS} - Allow {app_name}"
            filename = f"{self.MANAGED_LOGIN_ITEMS} - Allow {app_name}.mobileconfig"

        # Create merged profile
        profile_uuid = self.templates.generate_uuid()
        payload_uuid = self.templates.generate_uuid()

        merged_profile = self.templates.get_base_profile_structure(display_name, profile_uuid)

        service_payload = {
            'PayloadDisplayName': f'Service Management - {self.MANAGED_LOGIN_ITEMS}',
            'PayloadIdentifier': f'{self.SERVICE_MANAGEMENT_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': self.SERVICE_MANAGEMENT_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Rules': all_rules
        }

        merged_profile['PayloadContent'] = [service_payload]

        # Create merged profile dict
        return {
            'type': self.MANAGED_LOGIN_ITEMS,
            'filename': filename,
            'profile': merged_profile,
            'app_name': self.munki_item_name or login_items_profiles[0].get('app_name', 'Application'),
            'merged': True,
            'source_count': len(login_items_profiles)
        }

    def save_profiles(self, profiles: List[Dict] = None) -> List[str]:
        """
        Save generated profiles to disk in a folder named after the Munki item.

        Args:
            profiles: Optional list of profiles to save. Uses self.generated_profiles if None.

        Returns:
            List of saved file paths
        """
        if profiles is None:
            profiles = self.generated_profiles

        # Merge duplicate Managed Login Items profiles before saving
        profiles = self.merge_managed_login_items_profiles(profiles)

        # Create the output directory
        output_path = self._create_output_directory()

        logger.info(f"Saving profiles to: {output_path}")

        # Save individual profile files
        saved_files = self._save_profile_files(output_path, profiles)

        # Generate AutoPkg resources (EA script)
        saved_files = self._generate_autopkg_resources(output_path, saved_files)

        return saved_files

    def _create_output_directory(self) -> Path:
        """
        Create and return the output directory path based on Munki item name.

        Returns:
            Path to the output directory
        """
        # Create the base output directory
        base_output_path = Path(self.output_directory)

        # Create a folder named after the Munki item (no subfolder for profiles)
        if self.munki_item_name:
            # Clean the item name for use as a folder name (matching icon extraction logic)
            clean_name = self.munki_item_name.replace(' ', '_').replace('.app', '').replace('/', '_').replace('\\', '_')
            output_path = base_output_path / clean_name
        else:
            # Fallback to generic folder name
            output_path = base_output_path / "Config Profiles"

        # Ensure output directory exists with proper permissions
        from ..utils.file_helpers import FileHelpers

        # Create directory with proper user permissions (755 - readable by all, writable by owner)
        FileHelpers.create_directory_with_permissions(output_path)

        return output_path

    def _save_profile_files(self, output_path: Path, profiles: List[Dict]) -> List[str]:
        """
        Save individual profile files to disk.

        Args:
            output_path: Directory to save profiles to
            profiles: List of profile dictionaries to save

        Returns:
            List of saved file paths
        """
        saved_files = []

        for profile_info in profiles:
            try:
                filename = profile_info['filename']
                profile_data = profile_info['profile']

                # Create the file path
                file_path = output_path / filename

                # Save the profile as a plist
                with open(file_path, 'wb') as f:
                    plistlib.dump(profile_data, f)

                # Set proper file permissions (777 - full access, allows deletion without password)
                from ..utils.file_helpers import FileHelpers
                FileHelpers.set_file_permissions(file_path)

                saved_files.append(str(file_path))
                logger.info(f"Saved profile: {file_path}")

            except Exception as e:
                logger.error(f"Error saving profile {profile_info.get('filename', 'unknown')}: {e}")

        return saved_files

    def _generate_autopkg_resources(self, output_path: Path, saved_files: List[str]) -> List[str]:
        """
        Generate AutoPkg resources (EA script) if enabled.

        Args:
            output_path: Directory to save resources to
            saved_files: List of already saved file paths

        Returns:
            Updated list of saved file paths including generated resources
        """
        if saved_files and self.munki_item_name:
            try:
                # Generate Extension Attribute script if needed
                ea_script_path = self._generate_ea_script(output_path)
                if ea_script_path:
                    saved_files.append(ea_script_path)

            except Exception as e:
                logger.error(f"Error generating EA script: {e}")
                print(f"⚠️  Warning: Could not generate EA script: {e}")

        return saved_files

    def _generate_ea_script(self, output_path: Path) -> Optional[str]:
        """
        Generate Extension Attribute script if enabled and catalog item exists.

        Args:
            output_path: Directory to save the EA script to

        Returns:
            Path to generated EA script or None if not generated
        """
        from ..core.config_manager import get_config
        config = get_config()

        if not (self.catalog_item and config.is_ea_creation_enabled()):
            return None

        ea_gen = ExtensionAttributeGenerator()
        ea_result = ea_gen.generate_extension_attribute(
            catalog_item=self.catalog_item,
            munki_name=self.munki_item_name,
            output_dir=str(output_path)
        )

        if ea_result['generated']:
            ea_script_path = ea_result['path']
            logger.info(f"Generated Extension Attribute script: {ea_script_path}")
            return ea_script_path

        return None

    def generate_profile_summary(self, profiles: List[Dict] = None) -> str:
        """
        Generate a markdown summary of generated profiles.

        Args:
            profiles: Optional list of profiles. Uses self.generated_profiles if None.

        Returns:
            Markdown formatted summary
        """
        if profiles is None:
            profiles = self.generated_profiles

        if not profiles:
            return "## Configuration Profiles\n\nNo configuration profiles were generated.\n"

        summary = ["## Generated Configuration Profiles\n"]

        # Group profiles by application
        by_app = self._group_profiles_by_app(profiles)

        summary.append(f"**Total Profiles Generated:** {len(profiles)}\n")
        summary.append(f"**Applications Analyzed:** {len(by_app)}\n")

        for app_name, app_profiles in by_app.items():
            summary.append(f"### {app_name}\n")

            for profile in app_profiles:
                profile_type = profile['type']
                filename = profile['filename']
                summary.append(f"- **{profile_type}**: `{filename}`")

            summary.append("")  # Empty line between apps

        # Add profile type summary
        type_counts = self._count_profile_types(profiles)

        summary.append("### Profile Type Summary\n")
        for profile_type, count in sorted(type_counts.items()):
            summary.append(f"- **{profile_type}**: {count} profile(s)")

        summary.append("")

        return "\n".join(summary)

    def _group_profiles_by_app(self, profiles: List[Dict]) -> Dict[str, List[Dict]]:
        """Group profiles by application name."""
        by_app = {}
        for profile in profiles:
            # Handle both single app profiles and consolidated profiles
            if 'app_name' in profile:
                app_name = profile['app_name']
                if app_name not in by_app:
                    by_app[app_name] = []
                by_app[app_name].append(profile)
            elif 'apps' in profile:
                # For consolidated profiles, group under a consolidated heading
                consolidated_name = "Consolidated Profiles"
                if consolidated_name not in by_app:
                    by_app[consolidated_name] = []
                by_app[consolidated_name].append(profile)
        return by_app

    def _count_profile_types(self, profiles: List[Dict]) -> Dict[str, int]:
        """Count profiles by type."""
        type_counts = {}
        for profile in profiles:
            profile_type = profile['type']
            type_counts[profile_type] = type_counts.get(profile_type, 0) + 1
        return type_counts

    def get_profile_statistics(self, profiles: List[Dict] = None) -> Dict[str, Any]:
        """
        Get statistics about generated profiles.

        Args:
            profiles: Optional list of profiles. Uses self.generated_profiles if None.

        Returns:
            Dictionary containing various statistics
        """
        if profiles is None:
            profiles = self.generated_profiles

        stats = {
            'total_profiles': len(profiles),
            'total_applications': 0,
            'profile_types': {},
            'applications': {}
        }

        # Count by application
        by_app = {}
        for profile in profiles:
            profile_type = profile['type']

            # Handle both single app profiles and consolidated profiles
            if 'app_name' in profile:
                app_name = profile['app_name']
                # Count by app
                if app_name not in by_app:
                    by_app[app_name] = []
                by_app[app_name].append(profile_type)
            elif 'apps' in profile:
                # For consolidated profiles, count all the apps they cover
                for app_name in profile['apps']:
                    if app_name not in by_app:
                        by_app[app_name] = []
                    by_app[app_name].append(profile_type)

            # Count by type
            stats['profile_types'][profile_type] = stats['profile_types'].get(profile_type, 0) + 1

        stats['total_applications'] = len(by_app)
        stats['applications'] = by_app

        return stats

    def _determine_rule_type_from_item(self, item_type: str) -> str:
        """
        Determine the appropriate RuleType for a Managed Login Items profile rule.

        Args:
            item_type: The type of login item (e.g., "app (0x2)", "legacy agent (0x10008)", "LaunchAgent")

        Returns:
            "BundleIdentifier" for apps, "Label" for launch agents/daemons
        """
        item_type_lower = item_type.lower()

        # BTM types
        if 'app' in item_type_lower and '0x2' in item_type_lower:
            # BTM app type (0x2) → use BundleIdentifier
            return 'BundleIdentifier'
        elif 'agent' in item_type_lower or 'daemon' in item_type_lower:
            # BTM legacy agent (0x10008) or launch agents/daemons → use Label
            return 'Label'

        # Launch item types from system comparison
        if any(x in item_type_lower for x in ['launchagent', 'launchdaemon', 'userlaunchagent']):
            return 'Label'

        # Default to BundleIdentifier for unknown types
        return 'BundleIdentifier'

    def _extract_login_items_from_profile(self, profile_dict: Dict) -> List[Dict]:
        """
        Extract login items from an existing Managed Login Items profile.

        Args:
            profile_dict: Profile dictionary containing the profile data

        Returns:
            List of login item dictionaries compatible with profile generation
        """
        extracted_items = []

        try:
            profile = profile_dict.get('profile', {})
            payload_content = profile.get('PayloadContent', [])

            # Find the service management payload
            for payload in payload_content:
                if payload.get('PayloadType') == self.SERVICE_MANAGEMENT_PAYLOAD_TYPE:
                    rules = payload.get('Rules', [])

                    for rule in rules:
                        rule_type = rule.get('RuleType', 'BundleIdentifier')
                        rule_value = rule.get('RuleValue', '')
                        team_id = rule.get('TeamIdentifier', '')

                        if rule_value and team_id:
                            # Convert back to the format expected by profile generation
                            item = {
                                'bundle_id': rule_value,
                                'team_id': team_id,
                                'rule_type': rule_type,
                                'identifier': rule_value,
                                'type': 'existing_profile_item',
                                'detection_reason': 'Preserved from initial app scan',
                                'entitlement': 'preserved-from-scan'
                            }
                            extracted_items.append(item)
                            logger.debug(f"Extracted existing item: {rule_value} (team: {team_id}, rule: {rule_type})")

                    break  # Found the service management payload, no need to continue

            logger.info(f"Extracted {len(extracted_items)} items from existing profile")

        except Exception as e:
            logger.error(f"Error extracting login items from profile: {e}")

        return extracted_items

    def generate_enhanced_login_items_profile_from_system_data(self, app_name: str, bundle_id: str, team_id: str,
                                                               btm_data: str = None, initial_launch_items: set = None,
                                                               current_launch_items: set = None) -> Optional[Dict]:
        """
        Generate an enhanced Managed Login Items profile using existing system data.
        This leverages data already captured by the main testing workflow instead of duplicating capture logic.

        Note: This method only creates a profile with system-detected items. The merge_managed_login_items_profiles()
        method in save_profiles() will automatically merge this with any existing profiles.

        Args:
            app_name: Application name
            bundle_id: Application bundle identifier
            team_id: Application team identifier
            btm_data: BTM data already captured by system checks
            initial_launch_items: Initial launch items set from system checks
            current_launch_items: Current launch items set from system comparisons

        Returns:
            Profile information dictionary or None if no Login Items detected
        """
        from .app_analyzer import AppAnalyzer

        logger.info(f"Generating enhanced Login Items profile from system data for {app_name}")
        print(f"   bundle_id={bundle_id}, team_id={team_id}")
        print(f"   BTM data available: {btm_data is not None and len(btm_data) > 0 if btm_data else False}")
        print(f"   Initial launch items: {len(initial_launch_items) if initial_launch_items else 0}")
        print(f"   Current launch items: {len(current_launch_items) if current_launch_items else 0}")

        # Create analyzer instance to process existing system data
        analyzer = AppAnalyzer()

        all_login_items = []

        # 1. Extract Login Items from existing BTM data
        if btm_data:
            print("   📋 Extracting BTM login items...")
            btm_items = analyzer.get_login_items_from_system_data(
                btm_data, bundle_id, team_id=team_id, app_name=app_name
            )
            all_login_items.extend(btm_items)
            print(f"   ✅ Found {len(btm_items)} BTM items")

        # 2. Extract Launch items from existing system comparison data
        if initial_launch_items is not None and current_launch_items is not None:
            print("   📋 Extracting launch daemon/agent items...")
            launch_items = analyzer.get_launch_items_from_system_data(
                initial_launch_items, current_launch_items, bundle_id,
                team_id=team_id, app_name=app_name
            )
            all_login_items.extend(launch_items)
            print(f"   ✅ Found {len(launch_items)} launch items")

        # Note: We don't extract existing items here because the merge_managed_login_items_profiles()
        # method in save_profiles() will automatically merge all Managed Login Items profiles

        if not all_login_items:
            logger.info(f"No system Login Items detected for {app_name} from existing data")
            print(f"   ⚠️  No login items found for {app_name}")
            return None

        print(f"   🎯 Total login items found: {len(all_login_items)}")

        # Convert to the format expected by the profile template
        login_items_data = []
        for item in all_login_items:
            # Use the item's team_id if available, otherwise fall back to the app's team_id
            item_team_id = item.get('team_id', '') or team_id

            # Determine rule_type - prefer existing rule_type if already set, otherwise determine from item type
            item_type = item.get('type', '')
            if 'rule_type' in item and item['rule_type']:
                # Preserve existing rule_type from extracted profile or analyzer
                rule_type = item['rule_type']
            else:
                # Determine rule_type based on item type
                rule_type = self._determine_rule_type_from_item(item_type)

            item_dict = {
                'bundle_id': item.get('bundle_id', ''),
                'team_id': item_team_id,  # Use fallback team_id
                'btm_identifier': item.get('btm_identifier', ''),
                'identifier': item.get('identifier', ''),
                'type': item_type,
                'rule_type': rule_type,  # Add rule_type based on item characteristics
                'detection_reason': f"Detected via {item.get('source', 'system_data')} - {item.get('type', 'Login Item')}",
                'entitlement': f"system-detected-{item.get('source', 'unknown')}"
            }
            login_items_data.append(item_dict)
            print(f"     → {item_dict['bundle_id']} (team: {item_dict['team_id']}, rule: {rule_type})")

        logger.info(f"Found {len(login_items_data)} Login Items for {app_name} from system data")
        print(f"   ✅ Prepared {len(login_items_data)} items for profile template")

        try:
            # Create profile with only system-detected items
            # The merge_managed_login_items_profiles() method will merge this with the initial scan profile
            profile = self.templates.create_enhanced_managed_login_items_profile(
                app_name,
                login_items=[],  # Empty - only system-detected items in this profile
                system_detected_items=login_items_data
            )
            filename = f"{self.MANAGED_LOGIN_ITEMS} - Allow {app_name}.mobileconfig"

            return {
                'type': self.MANAGED_LOGIN_ITEMS,
                'filename': filename,
                'profile': profile,
                'app_name': app_name,
                'enhanced': True,  # Flag to indicate this is an enhanced profile
                'items_count': len(login_items_data),
                'data_source': 'system_captured'
            }

        except Exception as e:
            logger.error(f"Error generating enhanced Login Items profile for {app_name}: {e}")
            return None

    def update_profiles_with_system_data(self, app_name: str, bundle_id: str, team_id: str,
                                         btm_data: str = None, initial_launch_items: set = None,
                                         current_launch_items: set = None) -> List[Dict]:
        """
        Update generated profiles with system-level detection using existing captured data.
        This should be called after the application has been installed and run.

        Args:
            app_name: Application name
            bundle_id: Application bundle identifier
            team_id: Application team identifier
            btm_data: BTM data already captured by system checks
            initial_launch_items: Initial launch items set from system checks
            current_launch_items: Current launch items set from system comparisons

        Returns:
            List of updated/new profile information
        """
        logger.info(f"Updating profiles with system data for {app_name}")
        print(f"   🔍 Analyzing system-detected login items for: {app_name}")

        updated_profiles = []

        # Generate enhanced Login Items profile using existing system data
        # Don't extract existing items - the merge_managed_login_items_profiles() method
        # will merge all Managed Login Items profiles during save_profiles()
        enhanced_login_profile = self.generate_enhanced_login_items_profile_from_system_data(
            app_name, bundle_id, team_id, btm_data, initial_launch_items, current_launch_items
        )

        if enhanced_login_profile:
            # Don't remove the existing profile - add the enhanced profile alongside it
            # The merge_managed_login_items_profiles() method in save_profiles() will merge them
            enhanced_login_profile['app_name'] = app_name
            self.generated_profiles.append(enhanced_login_profile)
            updated_profiles.append(enhanced_login_profile)

            logger.info(f"Enhanced Login Items profile created with {enhanced_login_profile['items_count']} items")

        return updated_profiles
