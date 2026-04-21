# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Profile Templates for Configuration Profile Generation.

This module contains templates for generating various types of configuration profiles
based on the example profiles provided.
"""

import uuid
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ProfileTemplates:
    """Contains templates and utilities for generating configuration profiles."""

    # Constants for payload display names and types
    PPPC_DISPLAY_NAME = 'Privacy Preferences Policy Control'
    PPPC_PAYLOAD_TYPE = 'com.apple.TCC.configuration-profile-policy'
    SERVICE_MGMT_DISPLAY_NAME = 'Service Management - Managed Login Items'
    SERVICE_MGMT_PAYLOAD_TYPE = 'com.apple.servicemanagement'

    # Valid TCC service keys that can be managed via PPPC configuration profiles.
    # Location, Camera, and Microphone are NOT valid PPPC services.
    VALID_TCC_SERVICES = frozenset({
        'Accessibility', 'AddressBook', 'AppleEvents', 'Calendar',
        'ContactsFull', 'ContactsLimited', 'FileProviderDomain',
        'FileProviderPresence', 'ListenEvent', 'MediaLibrary',
        'Photos', 'PostEvent', 'Reminders', 'ScreenCapture',
        'SpeechRecognition', 'SystemPolicyAllFiles',
        'SystemPolicyDesktopFolder', 'SystemPolicyDocumentsFolder',
        'SystemPolicyDownloadsFolder', 'SystemPolicyNetworkVolumes',
        'SystemPolicyRemovableVolumes', 'SystemPolicySysAdminFiles',
    })

    @staticmethod
    def _get_organization() -> str:
        """Get organization name from config."""
        from ..core.config_manager import get_config
        config = get_config()
        return config.get_profile_organization()

    @staticmethod
    def _get_identifier_prefix() -> str:
        """Get reverse domain identifier prefix from config."""
        from ..core.config_manager import get_config
        config = get_config()
        return config.get_profile_identifier_prefix()

    @staticmethod
    def generate_uuid() -> str:
        """Generate a UUID for profile identifiers."""
        return str(uuid.uuid4()).upper()

    @staticmethod
    def get_base_profile_structure(display_name: str, profile_uuid: str = None) -> Dict[str, Any]:
        """
        Get the base structure for all configuration profiles.

        Args:
            display_name: The display name for the profile
            profile_uuid: Optional UUID, will generate if not provided

        Returns:
            Base profile dictionary structure
        """
        if not profile_uuid:
            profile_uuid = ProfileTemplates.generate_uuid()

        identifier_prefix = ProfileTemplates._get_identifier_prefix()
        organization = ProfileTemplates._get_organization()

        return {
            'PayloadContent': [],
            'PayloadDisplayName': display_name,
            'PayloadIdentifier': f"{identifier_prefix}.{profile_uuid}" if identifier_prefix else profile_uuid,
            'PayloadOrganization': organization,
            'PayloadScope': 'System',
            'PayloadType': 'Configuration',
            'PayloadUUID': profile_uuid,
            'PayloadVersion': 1,
            'TargetDeviceType': 5
        }

    @staticmethod
    def create_pppc_profile(app_name: str, pppc_requirements: List[Dict]) -> Dict[str, Any]:
        """
        Create a PPPC configuration profile.

        Args:
            app_name: Name of the application
            pppc_requirements: List of PPPC requirements with service, bundle_id, team_id

        Returns:
            Complete PPPC configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"PPPC - Allow {app_name}",
            profile_uuid
        )

        # Group requirements by service type
        services = {}
        for req in pppc_requirements:
            service = req['service']
            if service not in ProfileTemplates.VALID_TCC_SERVICES:
                logger.warning(f"Skipping invalid TCC service: {service}")
                continue
            bundle_id = req['bundle_id']
            team_id = req['team_id']

            if service not in services:
                services[service] = []

            # Generate code requirement string
            if team_id:
                code_requirement = (
                    f'identifier "{bundle_id}" and anchor apple generic and '
                    f'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                    f'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                    f'certificate leaf[subject.OU] = "{team_id}"'
                )
            else:
                code_requirement = f'identifier "{bundle_id}" and anchor apple'

            # Get allowed status from requirement (defaults to True if not specified)
            # Camera and Microphone should have allowed=False (deny-only)
            allowed = req.get('allowed', True)
            authorization = 'Allow' if allowed else 'Deny'

            # Build service entry
            service_entry = {
                'Allowed': allowed,
                'Authorization': authorization,
                'CodeRequirement': code_requirement,
                'Identifier': bundle_id,
                'IdentifierType': 'bundleID',
                'StaticCode': False
            }

            # For AppleEvents, add receiver information if available
            if service == 'AppleEvents' and req.get('ae_receiver_bundle_id'):
                ae_receiver_team_id = req.get('ae_receiver_team_id')
                if ae_receiver_team_id:
                    ae_code_requirement = (
                        f'identifier "{req["ae_receiver_bundle_id"]}" and anchor apple generic and '
                        f'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                        f'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                        f'certificate leaf[subject.OU] = {ae_receiver_team_id}'
                    )
                else:
                    ae_code_requirement = f'identifier "{req["ae_receiver_bundle_id"]}" and anchor apple generic'

                service_entry.update({
                    'AEReceiverCodeRequirement': ae_code_requirement,
                    'AEReceiverIdentifier': req['ae_receiver_bundle_id'],
                    'AEReceiverIdentifierType': 'bundleID'
                })
            elif service == 'AppleEvents':
                # Skip AppleEvents without receiver - these should be handled as warnings
                continue

            services[service].append(service_entry)

        # Create the PPPC payload
        pppc_payload = {
            'PayloadDisplayName': ProfileTemplates.PPPC_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.PPPC_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.PPPC_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Services': services
        }

        profile['PayloadContent'] = [pppc_payload]
        return profile

    @staticmethod
    def create_notifications_profile(app_name: str, bundle_ids) -> Dict[str, Any]:
        """
        Create a Notifications configuration profile.

        Args:
            app_name: Name of the application
            bundle_ids: Bundle identifier(s) of the application(s) - can be string or list

        Returns:
            Complete Notifications configuration profile
        """
        # Ensure bundle_ids is a list
        if isinstance(bundle_ids, str):
            bundle_ids = [bundle_ids]
        elif not isinstance(bundle_ids, list):
            bundle_ids = [str(bundle_ids)]

        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"Notifications - Allow {app_name}",
            profile_uuid
        )

        # Create notification settings for each bundle ID
        notification_settings = []
        for bundle_id in bundle_ids:
            notification_settings.append({
                'AlertType': 1,
                'BadgesEnabled': True,
                'BundleIdentifier': bundle_id,
                'CriticalAlertEnabled': True,
                'GroupingType': 0,
                'NotificationsEnabled': True,
                'PreviewType': 1,
                'ShowInLockScreen': True,
                'ShowInNotificationCenter': True,
                'SoundsEnabled': True
            })

        # Create the notifications payload
        notifications_payload = {
            'NotificationSettings': notification_settings,
            'PayloadDisplayName': 'Notifications',
            'PayloadIdentifier': f'com.apple.notificationsettings.{payload_uuid}',
            'PayloadType': 'com.apple.notificationsettings',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }

        profile['PayloadContent'] = [notifications_payload]
        return profile

    @staticmethod
    def create_system_extension_profile(app_name: str, team_ids: List[str]) -> Dict[str, Any]:
        """
        Create a System Extension configuration profile.

        Args:
            app_name: Name of the application
            team_ids: List of Team IDs to allow

        Returns:
            Complete System Extension configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"System Extension - Allow {app_name}",
            profile_uuid
        )

        # Create the system extension payload
        sysext_payload = {
            'AllowUserOverrides': True,
            'AllowedTeamIdentifiers': team_ids,
            'PayloadDisplayName': 'System Extension Policy',
            'PayloadIdentifier': f'com.apple.system-extension-policy.{payload_uuid}',
            'PayloadType': 'com.apple.system-extension-policy',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }

        profile['PayloadContent'] = [sysext_payload]
        return profile

    @staticmethod
    def create_kernel_extension_profile(app_name: str, team_ids: List[str], bundle_ids: List[str] = None) -> Dict[str, Any]:
        """
        Create a Kernel Extension configuration profile.

        Args:
            app_name: Name of the application
            team_ids: List of Team IDs to allow
            bundle_ids: Optional list of specific bundle IDs to allow

        Returns:
            Complete Kernel Extension configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"Kernel Extension - {app_name}",
            profile_uuid
        )

        # Create the kernel extension payload
        kext_payload = {
            'AllowedTeamIdentifiers': team_ids,
            'PayloadDisplayName': 'Kernel Extension Policy',
            'PayloadIdentifier': f'com.apple.syspolicy.kernel-extension-policy.{payload_uuid}',
            'PayloadType': 'com.apple.syspolicy.kernel-extension-policy',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }

        # Add specific bundle IDs if provided
        if bundle_ids:
            kext_payload['AllowedKernelExtensions'] = {}
            for team_id in team_ids:
                kext_payload['AllowedKernelExtensions'][team_id] = bundle_ids

        profile['PayloadContent'] = [kext_payload]
        return profile

    @staticmethod
    def create_screen_recording_profile(app_name: str, bundle_id: str, team_id: str = None) -> Dict[str, Any]:
        """
        Create a Screen Recording configuration profile.

        Args:
            app_name: Name of the application
            bundle_id: Bundle identifier of the application
            team_id: Team identifier for code signing (optional)

        Returns:
            Complete Screen Recording configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"Screen Recording - Allow {app_name}",
            profile_uuid
        )

        # Generate code requirement string (same format as PPPC profiles)
        if team_id:
            code_requirement = (
                f'identifier "{bundle_id}" and anchor apple generic and '
                f'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                f'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                f'certificate leaf[subject.OU] = {team_id}'
            )
        else:
            code_requirement = f'identifier "{bundle_id}" and anchor apple generic'

        # Create the screen recording PPPC payload
        pppc_payload = {
            'PayloadDisplayName': ProfileTemplates.PPPC_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.PPPC_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.PPPC_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Services': {
                'ScreenCapture': [
                    {
                        'Authorization': 'AllowStandardUserToSetSystemService',
                        'CodeRequirement': code_requirement,
                        'Identifier': bundle_id,
                        'IdentifierType': 'bundleID',
                        'StaticCode': False
                    }
                ]
            }
        }

        profile['PayloadContent'] = [pppc_payload]
        return profile

    @staticmethod
    def create_content_filter_profile(app_name: str, bundle_id: str, team_id: str) -> Dict[str, Any]:
        """
        Create a Content Filter configuration profile.

        Args:
            app_name: Name of the application
            bundle_id: Bundle identifier of the application
            team_id: Team identifier of the application

        Returns:
            Complete Content Filter configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"Content Filter - {app_name}",
            profile_uuid
        )

        # Create the web content filter payload
        filter_payload = {
            'FilterBrowsers': True,
            'FilterSockets': True,
            'FilterType': 'Plugin',
            'Organization': ProfileTemplates.ORGANIZATION,
            'PayloadDisplayName': 'Web Content Filter',
            'PayloadIdentifier': f'com.apple.webcontent-filter.{payload_uuid}',
            'PayloadType': 'com.apple.webcontent-filter',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'PluginBundleID': bundle_id,
            'UserDefinedName': f'{app_name} Content Filter'
        }

        profile['PayloadContent'] = [filter_payload]
        return profile

    @staticmethod
    def create_managed_login_items_profile(app_name: str, login_items: List[Dict]) -> Dict[str, Any]:
        """
        Create a Service Management - Managed Login Items configuration profile.

        Args:
            app_name: Name of the application
            login_items: List of login items with bundle_id and team_id

        Returns:
            Complete Service Management configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"Managed Login Items - Allow {app_name}",
            profile_uuid
        )

        # Create rules using the appropriate RuleType (Label for LaunchAgents/Daemons, BundleIdentifier for apps)
        rules = []
        added_rule_keys = set()  # Track (rule_type, bundle_id) tuples to allow same bundle_id with different rule types

        # Create one rule per identifier
        for item in login_items:
            bundle_id = item.get('bundle_id', '')
            team_id = item.get('team_id', '')
            rule_type = item.get('rule_type', 'BundleIdentifier')  # Default to BundleIdentifier for backward compatibility

            logger.info(f"DEBUG: Processing item - bundle_id={bundle_id}, team_id={team_id}, rule_type={rule_type}")

            # Create unique key combining rule type and bundle ID
            rule_key = (rule_type, bundle_id)

            # Add rule if we have both identifier and team_id, and this specific rule combination hasn't been added
            if bundle_id and team_id and rule_key not in added_rule_keys:
                rules.append({
                    'RuleType': rule_type,
                    'RuleValue': bundle_id,
                    'TeamIdentifier': team_id
                })
                added_rule_keys.add(rule_key)
                logger.info(f"Added {rule_type} rule: {bundle_id} (team: {team_id})")

        # Create the service management payload (com.apple.servicemanagement)
        service_payload = {
            'PayloadDisplayName': ProfileTemplates.SERVICE_MGMT_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.SERVICE_MGMT_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.SERVICE_MGMT_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Rules': rules
        }

        profile['PayloadContent'] = [service_payload]
        return profile

    @staticmethod
    def _get_bundle_prefix(bundle_ids: List[str]) -> str:
        """
        Extract the common prefix from bundle identifiers.

        Args:
            bundle_ids: List of bundle identifiers

        Returns:
            Common prefix suitable for prefix rules
        """
        if not bundle_ids:
            return ''

        if len(bundle_ids) == 1:
            # For single bundle ID, use the company prefix (e.g., com.autodesk)
            parts = bundle_ids[0].split('.')
            if len(parts) >= 2:
                return '.'.join(parts[:2])  # e.g., "com.autodesk" from "com.autodesk.AutoCAD"
            return bundle_ids[0]

        # For multiple bundle IDs, find common prefix
        prefix = bundle_ids[0]
        for bundle_id in bundle_ids[1:]:
            while not bundle_id.startswith(prefix) and prefix:
                prefix = prefix[:-1]

        # Ensure we end at a logical boundary (dot)
        if '.' in prefix:
            prefix = prefix.rsplit('.', 1)[0]

        return prefix if prefix else bundle_ids[0].split('.')[0]

    @staticmethod
    def create_enhanced_managed_login_items_profile(app_name: str, login_items: List[Dict], system_detected_items: List[Dict] = None) -> Dict[str, Any]:
        """
        Create an enhanced Service Management - Managed Login Items configuration profile
        that uses exact identifiers when available from system monitoring.

        Args:
            app_name: Name of the application
            login_items: List of login items from static analysis
            system_detected_items: List of login items detected from BTM/BlockBlock monitoring

        Returns:
            Complete Service Management configuration profile with exact rules when possible
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        profile = ProfileTemplates.get_base_profile_structure(
            f"Managed Login Items - Allow {app_name}",
            profile_uuid
        )

        rules = []
        added_rule_keys = set()  # Track (rule_type, bundle_id) tuples to allow same bundle_id with different rule types

        # Combine all login items data
        all_items = login_items.copy()
        if system_detected_items:
            all_items.extend(system_detected_items)

        # Strategy: Use exact rules based on detected type (BundleIdentifier for apps, Label for LaunchAgents/Daemons)
        # Extract all unique rules from all sources
        for item in all_items:
            bundle_id = item.get('bundle_id', '')
            team_id = item.get('team_id', '')
            rule_type = item.get('rule_type', 'BundleIdentifier')  # Default to BundleIdentifier if not specified

            # Create unique key combining rule type and bundle ID
            rule_key = (rule_type, bundle_id)

            # Add rule if we have both bundle_id and team_id, and this specific rule combination hasn't been added
            if bundle_id and team_id and rule_key not in added_rule_keys:
                rules.append({
                    'RuleType': rule_type,
                    'RuleValue': bundle_id,
                    'TeamIdentifier': team_id
                })
                added_rule_keys.add(rule_key)
                logger.info(f"Added {rule_type} rule: {bundle_id} (team: {team_id})")

        # Create the service management payload
        service_payload = {
            'PayloadDisplayName': ProfileTemplates.SERVICE_MGMT_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.SERVICE_MGMT_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.SERVICE_MGMT_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Rules': rules
        }

        profile['PayloadContent'] = [service_payload]
        return profile

    @staticmethod
    def create_consolidated_pppc_profile(pppc_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated PPPC configuration profile for multiple applications.

        Args:
            pppc_requirements: List of PPPC requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated PPPC configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in pppc_requirements})
            if len(app_names) == 1:
                profile_display_name = f"PPPC - Allow {app_names[0]}"
            else:
                profile_display_name = f"PPPC - Allow {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # Group requirements by service type and deduplicate by bundle_id
        # This is correct for consolidated profiles - allows multiple apps with same service,
        # but prevents same app from appearing twice in same service
        services = {}
        for req in pppc_requirements:
            service = req['service']
            if service not in ProfileTemplates.VALID_TCC_SERVICES:
                logger.warning(f"Skipping invalid TCC service: {service}")
                continue
            bundle_id = req['bundle_id']
            team_id = req['team_id']

            if service not in services:
                services[service] = []

            # Check if this bundle_id is already in this service to prevent duplicates
            existing_bundle_ids = [entry.get('Identifier') for entry in services[service]]
            if bundle_id in existing_bundle_ids:
                # Skip duplicate bundle_id for the same service
                continue

            # Generate code requirement string
            if team_id:
                code_requirement = (
                    f'identifier "{bundle_id}" and anchor apple generic and '
                    f'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                    f'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                    f'certificate leaf[subject.OU] = {team_id}'
                )
            else:
                code_requirement = f'identifier "{bundle_id}" and anchor apple generic'

            # Get allowed status from requirement (defaults to True if not specified)
            # Camera and Microphone should have allowed=False (deny-only)
            allowed = req.get('allowed', True)
            authorization = 'Allow' if allowed else 'Deny'

            # Build service entry
            service_entry = {
                'Allowed': allowed,
                'Authorization': authorization,
                'CodeRequirement': code_requirement,
                'Identifier': bundle_id,
                'IdentifierType': 'bundleID',
                'StaticCode': False
            }

            # For AppleEvents, add receiver information if available
            if service == 'AppleEvents' and req.get('ae_receiver_bundle_id'):
                ae_receiver_team_id = req.get('ae_receiver_team_id')
                if ae_receiver_team_id:
                    ae_code_requirement = (
                        f'identifier "{req["ae_receiver_bundle_id"]}" and anchor apple generic and '
                        f'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                        f'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                        f'certificate leaf[subject.OU] = {ae_receiver_team_id}'
                    )
                else:
                    ae_code_requirement = f'identifier "{req["ae_receiver_bundle_id"]}" and anchor apple generic'

                service_entry.update({
                    'AEReceiverCodeRequirement': ae_code_requirement,
                    'AEReceiverIdentifier': req['ae_receiver_bundle_id'],
                    'AEReceiverIdentifierType': 'bundleID'
                })
            elif service == 'AppleEvents':
                # Skip AppleEvents without receiver - these should be handled as warnings
                continue

            services[service].append(service_entry)

        # Create the PPPC payload
        pppc_payload = {
            'PayloadDisplayName': ProfileTemplates.PPPC_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.PPPC_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.PPPC_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Services': services
        }

        profile['PayloadContent'] = [pppc_payload]
        return profile

    @staticmethod
    def create_consolidated_screen_recording_profile(screen_recording_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated Screen Recording configuration profile for multiple applications.

        Args:
            screen_recording_requirements: List of screen recording requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated Screen Recording configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in screen_recording_requirements})
            if len(app_names) == 1:
                profile_display_name = f"Screen Recording - Allow {app_names[0]}"
            else:
                profile_display_name = f"Screen Recording - Allow {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # Build screen capture entries for all apps
        screen_capture_entries = []
        for req in screen_recording_requirements:
            bundle_id = req['bundle_id']
            team_id = req['team_id']

            # Generate code requirement string (same format as PPPC profiles)
            if team_id:
                code_requirement = (
                    f'identifier "{bundle_id}" and anchor apple generic and '
                    f'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
                    f'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
                    f'certificate leaf[subject.OU] = {team_id}'
                )
            else:
                code_requirement = f'identifier "{bundle_id}" and anchor apple generic'

            screen_capture_entries.append({
                'Authorization': 'AllowStandardUserToSetSystemService',
                'CodeRequirement': code_requirement,
                'Identifier': bundle_id,
                'IdentifierType': 'bundleID',
                'StaticCode': False
            })

        # Create the screen recording PPPC payload
        pppc_payload = {
            'PayloadDisplayName': ProfileTemplates.PPPC_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.PPPC_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.PPPC_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Services': {
                'ScreenCapture': screen_capture_entries
            }
        }

        profile['PayloadContent'] = [pppc_payload]
        return profile

    @staticmethod
    def create_consolidated_notifications_profile(notifications_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated Notifications configuration profile for multiple applications.

        Args:
            notifications_requirements: List of notifications requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated Notifications configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in notifications_requirements})
            if len(app_names) == 1:
                profile_display_name = f"Notifications - Allow {app_names[0]}"
            else:
                profile_display_name = f"Notifications - Allow {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # Collect notification settings for all applications
        notification_settings = []
        for req in notifications_requirements:
            bundle_id = req['bundle_id']
            if bundle_id:  # Only add if bundle ID exists
                notification_settings.append({
                    'AlertType': 1,
                    'BadgesEnabled': True,
                    'BundleIdentifier': bundle_id,
                    'CriticalAlertEnabled': True,
                    'GroupingType': 0,
                    'NotificationsEnabled': True,
                    'PreviewType': 1,
                    'ShowInLockScreen': True,
                    'ShowInNotificationCenter': True,
                    'SoundsEnabled': True
                })

        # Create the notifications payload
        notifications_payload = {
            'NotificationSettings': notification_settings,
            'PayloadDisplayName': 'Notifications',
            'PayloadIdentifier': f'com.apple.notificationsettings.{payload_uuid}',
            'PayloadType': 'com.apple.notificationsettings',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }

        profile['PayloadContent'] = [notifications_payload]
        return profile

    @staticmethod
    def create_consolidated_managed_login_items_profile(login_items_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated Managed Login Items configuration profile for multiple applications.

        Args:
            login_items_requirements: List of login items requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated Managed Login Items configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in login_items_requirements})
            if len(app_names) == 1:
                profile_display_name = f"Managed Login Items - Allow {app_names[0]}"
            else:
                profile_display_name = f"Managed Login Items - Allow {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # Create rules using BundleIdentifier with exact bundle IDs
        rules = []
        added_bundle_ids = set()

        # Create one rule per bundle ID
        for req in login_items_requirements:
            team_id = req.get('team_id', '')
            bundle_id = req.get('bundle_id', '')

            # Add bundle ID rule if we have both bundle_id and team_id
            if bundle_id and team_id and bundle_id not in added_bundle_ids:
                rules.append({
                    'RuleType': 'BundleIdentifier',
                    'RuleValue': bundle_id,
                    'TeamIdentifier': team_id
                })
                added_bundle_ids.add(bundle_id)
                logger.info(f"Added BundleIdentifier rule: {bundle_id} (team: {team_id})")

        # Create the service management payload
        service_payload = {
            'PayloadDisplayName': ProfileTemplates.SERVICE_MGMT_DISPLAY_NAME,
            'PayloadIdentifier': f'{ProfileTemplates.SERVICE_MGMT_PAYLOAD_TYPE}.{payload_uuid}',
            'PayloadType': ProfileTemplates.SERVICE_MGMT_PAYLOAD_TYPE,
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'Rules': rules
        }

        profile['PayloadContent'] = [service_payload]
        return profile

    @staticmethod
    def create_consolidated_system_extension_profile(system_extension_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated System Extension configuration profile for multiple applications.

        Args:
            system_extension_requirements: List of system extension requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated System Extension configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in system_extension_requirements})
            if len(app_names) == 1:
                profile_display_name = f"System Extension - Allow {app_names[0]}"
            else:
                profile_display_name = f"System Extension - Allow {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # Collect all unique team IDs
        team_ids = list({req['team_id'] for req in system_extension_requirements if req.get('team_id')})

        # Create the system extension payload
        organization = ProfileTemplates._get_organization()
        sysext_payload = {
            'AllowUserOverrides': True,
            'AllowedTeamIdentifiers': team_ids,
            'PayloadDisplayName': 'System Extensions',
            'PayloadIdentifier': payload_uuid,
            'PayloadOrganization': organization,
            'PayloadType': 'com.apple.system-extension-policy',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }

        profile['PayloadContent'] = [sysext_payload]
        return profile

    @staticmethod
    def create_consolidated_kernel_extension_profile(kernel_extension_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated Kernel Extension configuration profile for multiple applications.

        Args:
            kernel_extension_requirements: List of kernel extension requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated Kernel Extension configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in kernel_extension_requirements})
            if len(app_names) == 1:
                profile_display_name = f"Kernel Extension - {app_names[0]}"
            else:
                profile_display_name = f"Kernel Extension - {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # Collect all unique team IDs
        team_ids = list({req['team_id'] for req in kernel_extension_requirements if req.get('team_id')})

        # Create the kernel extension payload
        kext_payload = {
            'AllowedTeamIdentifiers': team_ids,
            'PayloadDisplayName': 'Kernel Extension Policy',
            'PayloadIdentifier': f'com.apple.syspolicy.kernel-extension-policy.{payload_uuid}',
            'PayloadType': 'com.apple.syspolicy.kernel-extension-policy',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1
        }

        # Collect bundle IDs if available in extension_data
        bundle_ids_by_team = {}
        for req in kernel_extension_requirements:
            team_id = req.get('team_id')
            extension_data = req.get('extension_data', {})
            bundle_id = extension_data.get('bundle_id')

            if team_id and bundle_id:
                if team_id not in bundle_ids_by_team:
                    bundle_ids_by_team[team_id] = []
                if bundle_id not in bundle_ids_by_team[team_id]:
                    bundle_ids_by_team[team_id].append(bundle_id)

        # Add specific bundle IDs if available
        if bundle_ids_by_team:
            kext_payload['AllowedKernelExtensions'] = bundle_ids_by_team

        profile['PayloadContent'] = [kext_payload]
        return profile

    @staticmethod
    def create_consolidated_content_filter_profile(content_filter_requirements: List[Dict], display_name: str = None) -> Dict[str, Any]:
        """
        Create a consolidated Content Filter configuration profile for multiple applications.

        Args:
            content_filter_requirements: List of content filter requirements from multiple apps
            display_name: Optional custom display name for the profile

        Returns:
            Complete consolidated Content Filter configuration profile
        """
        profile_uuid = ProfileTemplates.generate_uuid()
        payload_uuid = ProfileTemplates.generate_uuid()

        # Use provided display name or generate one based on app names
        if display_name:
            profile_display_name = display_name
        else:
            app_names = list({req['app_name'] for req in content_filter_requirements})
            if len(app_names) == 1:
                profile_display_name = f"Content Filter - {app_names[0]}"
            else:
                profile_display_name = f"Content Filter - {len(app_names)} Applications"

        profile = ProfileTemplates.get_base_profile_structure(profile_display_name, profile_uuid)

        # For content filter profiles, we need to determine the extension bundle ID
        # Use the first application's extension data if available
        first_req = content_filter_requirements[0]
        extensions = first_req.get('extensions', [])

        if extensions:
            # Use the first content filter extension found
            extension = extensions[0]
            filter_provider_bundle_id = extension['bundle_id']
            plugin_bundle_id = first_req['bundle_id']  # Main app bundle ID
        else:
            # Fallback to main app bundle ID if no extensions found
            filter_provider_bundle_id = first_req['bundle_id']
            plugin_bundle_id = first_req['bundle_id']

        # Create the web content filter payload matching the LuLu example structure
        organization = ProfileTemplates._get_organization()
        filter_payload = {
            'FilterDataProviderBundleIdentifier': filter_provider_bundle_id,
            'FilterDataProviderDesignatedRequirement': f'anchor apple generic and identifier "{filter_provider_bundle_id}" and (certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = {first_req["team_id"]})',
            'FilterPackets': False,
            'FilterSockets': True,
            'FilterType': 'Plugin',
            'PayloadDisplayName': 'Web Content Filter Payload',
            'PayloadIdentifier': payload_uuid,
            'PayloadOrganization': organization,
            'PayloadType': 'com.apple.webcontent-filter',
            'PayloadUUID': payload_uuid,
            'PayloadVersion': 1,
            'PluginBundleID': plugin_bundle_id,
            'UserDefinedName': first_req['app_name'],
            'VendorConfig': {}
        }

        profile['PayloadContent'] = [filter_payload]
        return profile
