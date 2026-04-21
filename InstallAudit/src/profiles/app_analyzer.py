# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Application Analyzer for Configuration Profile Generation.

This module analyzes macOS applications to detect requirements for various
configuration profile types including PPPC, System Extensions, Notifications, etc.
"""

import os
import subprocess
import plistlib
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AppAnalyzer:
    """Analyzes macOS applications to determine configuration profile requirements."""

    # Common string constants (defined first to be used in dictionaries and sets below)
    ENTITLEMENT_SYSTEM_EXT_INSTALL = 'com.apple.developer.system-extension.install'
    ENTITLEMENT_NETWORK_EXTENSION = 'com.apple.developer.networking.networkextension'
    ENTITLEMENT_APPLE_EVENTS = 'com.apple.security.automation.apple-events'
    CODESIGN_PATH = '/usr/bin/codesign'
    TEAM_IDENTIFIER_PREFIX = 'TeamIdentifier='
    SYSTEM_EXTENSION_SUFFIX = '.systemextension'
    PLIST_SUFFIX = '.plist'

    # PPPC entitlements that can be set to "Allow" (not deny-only)
    ALLOWABLE_PPPC_ENTITLEMENTS = {
        # Personal Information
        'com.apple.security.personal-information.addressbook': 'AddressBook',
        'com.apple.security.personal-information.calendars': 'Calendar',
        'com.apple.security.personal-information.photos-library': 'Photos',
        'com.apple.security.personal-information.reminders': 'Reminders',
        'com.apple.security.personal-information.location': 'Location',
        'com.apple.developer.contacts.notes': 'AddressBook',

        # Device Access (Camera and Microphone excluded - PPPC can only deny these, not allow)
        'com.apple.security.device.bluetooth': 'BluetoothAlways',

        # File System Access
        'com.apple.security.files.all': 'SystemPolicyAllFiles',
        'com.apple.security.files.user-selected.read-only': 'FileProviderPresence',
        'com.apple.security.files.user-selected.read-write': 'FileProviderPresence',
        'com.apple.security.files.user-selected': 'FileProviderPresence',
        'com.apple.security.files.downloads.read-only': 'SystemPolicyDownloadsFolder',
        'com.apple.security.files.downloads.read-write': 'SystemPolicyDownloadsFolder',
        'com.apple.security.files.desktop.read-only': 'SystemPolicyDesktopFolder',
        'com.apple.security.files.desktop.read-write': 'SystemPolicyDesktopFolder',
        'com.apple.security.files.documents.read-only': 'SystemPolicyDocumentsFolder',
        'com.apple.security.files.documents.read-write': 'SystemPolicyDocumentsFolder',
        'com.apple.security.root': 'SystemPolicySysAdminFiles',

        # System Policy Access
        'com.apple.security.files.app-bundles': 'SystemPolicyAppBundles',
        'com.apple.security.files.app-data': 'SystemPolicyAppData',
        'com.apple.security.files.network-volumes': 'SystemPolicyNetworkVolumes',
        'com.apple.security.files.removable-volumes': 'SystemPolicyRemovableVolumes',

        # Media Assets
        'com.apple.security.assets.music.read-only': 'MediaLibrary',
        'com.apple.security.assets.music.read-write': 'MediaLibrary',
        'com.apple.security.assets.movies.read-only': 'MediaLibrary',
        'com.apple.security.assets.movies.read-write': 'MediaLibrary',
        'com.apple.security.assets.pictures.read-only': 'SystemPolicyDesktopFolder',
        'com.apple.security.assets.pictures.read-write': 'SystemPolicyDesktopFolder',

        # Automation and Events
        ENTITLEMENT_APPLE_EVENTS: 'AppleEvents',
        'com.apple.security.automation.application-scripting': 'AppleEvents',
        'com.apple.security.automation.post-events': 'PostEvent',
        'com.apple.security.automation.listen-events': 'ListenEvent',

        # Accessibility and Recognition
        'com.apple.security.accessibility': 'Accessibility',
        'com.apple.security.speech-recognition': 'SpeechRecognition'
    }

    # System extension entitlements
    SYSTEM_EXTENSION_ENTITLEMENTS = {
        ENTITLEMENT_SYSTEM_EXT_INSTALL,
        'com.apple.developer.driverkit',
        'com.apple.developer.driverkit.usb',
        'com.apple.developer.driverkit.serial',
        'com.apple.developer.driverkit.audio',
        'com.apple.developer.driverkit.family.networking',
        ENTITLEMENT_NETWORK_EXTENSION,
        'com.apple.developer.endpoint-security.client'
    }

    # Kernel extension related identifiers
    KERNEL_EXTENSION_IDENTIFIERS = {
        'com.apple.developer.kernel-extension',
        'com.apple.kext.explicit-consent',
        'com.apple.kext.allow-user-load'
    }

    # Content filter entitlements
    CONTENT_FILTER_ENTITLEMENTS = {
        ENTITLEMENT_NETWORK_EXTENSION,
        'com.apple.developer.web-content-filter',
        'com.apple.developer.networking.custom-protocol'
    }

    # Screen recording entitlements
    SCREEN_RECORDING_ENTITLEMENTS = {
        'com.apple.security.device.screen-capture',
        'com.apple.developer.avfoundation.multitasking-camera-access'
    }

    # Login items entitlements
    LOGIN_ITEMS_ENTITLEMENTS = {
        'com.apple.developer.login-items',
        ENTITLEMENT_APPLE_EVENTS,
        'com.apple.servicemanagement'
    }

    def __init__(self):
        """Initialize the AppAnalyzer."""
        self.analysis_results = {}

    def analyze_application(self, app_path: str) -> Dict:
        """
        Analyze an application to determine configuration profile requirements.

        Args:
            app_path: Path to the .app bundle

        Returns:
            Dictionary containing analysis results and detected requirements
        """
        logger.info(f"Starting analysis of {app_path}")

        if not os.path.exists(app_path):
            logger.error(f"Application not found at {app_path}")
            return {}

        if not app_path.endswith('.app'):
            logger.error(f"Path does not appear to be an application bundle: {app_path}")
            return {}

        results = {
            'app_path': app_path,
            'app_name': os.path.basename(app_path),
            'bundle_info': {},
            'entitlements': {},
            'code_signing': {},
            'embedded_profile': {},
            'required_profiles': {},
            'frameworks': [],
            'analysis_errors': [],
            'manual_review_warnings': []
        }

        try:
            # Extract bundle information
            results['bundle_info'] = self._extract_bundle_info(app_path)

            # Extract entitlements
            results['entitlements'] = self._extract_entitlements(app_path)

            # Get code signing information
            results['code_signing'] = self._extract_code_signing_info(app_path)

            # Check Rosetta requirements (after we have bundle ID from code signing)
            results['rosetta_info'] = self._check_rosetta_requirements(results['code_signing'])

            # Check for embedded provisioning profile
            results['embedded_profile'] = self._extract_embedded_profile(app_path)

            # Analyze linked frameworks
            results['frameworks'] = self._analyze_frameworks(app_path)

            # Determine required configuration profiles
            results['required_profiles'] = self._determine_required_profiles(results)

            # Log Rosetta information if available
            rosetta_info = results.get('rosetta_info', {})
            detection_method = rosetta_info.get('detection_method')

            if detection_method in ['intel_system_skipped', 'intel_system_no_arch_info']:
                # Intel system - no Rosetta detection needed, but may have arch info
                if rosetta_info.get('detection_supported'):
                    reason = rosetta_info.get('rosetta_reason', '')
                    if '⚠️' in reason:
                        # ARM-only app on Intel - won't run!
                        logger.warning(reason)
                    else:
                        logger.info(f"ℹ️  {reason}")
                else:
                    logger.debug("Intel system - no architecture information available")
            elif rosetta_info.get('detection_supported'):
                if rosetta_info.get('requires_rosetta'):
                    logger.info(f"🔄 Rosetta required: {rosetta_info.get('rosetta_reason', 'Unknown reason')}")
                    if rosetta_info.get('rosetta_override'):
                        logger.info(f"   Override type: {rosetta_info.get('rosetta_override')}")
                    if not rosetta_info.get('has_native_version', True):
                        logger.warning("⚠️  No native Apple Silicon version available")
                else:
                    logger.info(f"✅ Runs natively on Apple Silicon: {rosetta_info.get('rosetta_reason', '')}")
            elif detection_method == 'system_profiler_unavailable':
                logger.debug("Rosetta detection not supported on this macOS version")
            elif detection_method in ['no_bundle_id', 'no_bundle_id_or_architecture']:
                logger.debug("Rosetta detection skipped - insufficient information available")

        except Exception as e:
            logger.error(f"Error analyzing application {app_path}: {e}")
            results['analysis_errors'].append(str(e))

        return results

    def _extract_bundle_info(self, app_path: str) -> Dict:
        """Extract information from the app's Info.plist."""
        info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')

        if not os.path.exists(info_plist_path):
            logger.warning(f"Info.plist not found at {info_plist_path}")
            return {}

        try:
            with open(info_plist_path, 'rb') as f:
                return plistlib.load(f)
        except Exception as e:
            logger.error(f"Error reading Info.plist: {e}")
            return {}

    def _extract_entitlements(self, app_path: str) -> Dict:
        """Extract entitlements from the application's code signature."""
        try:
            result = subprocess.run(
                [self.CODESIGN_PATH, '-d', '--entitlements', '-', app_path],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                logger.debug(f"No entitlements found or failed to extract: {result.stderr.strip() if result.stderr else 'No error message'}")
                return {}

            # Parse the entitlements XML
            if result.stdout.strip():
                try:
                    # Handle different output formats
                    lines = result.stdout.strip().split('\n')
                    xml_content = result.stdout.strip()

                    # Remove executable line if present
                    if lines and lines[0].startswith('Executable='):
                        xml_content = '\n'.join(lines[1:])

                    # Try to find XML content
                    xml_start = xml_content.find('<?xml')
                    if xml_start != -1:
                        xml_content = xml_content[xml_start:]
                    elif xml_content.find('<plist') != -1:
                        xml_start = xml_content.find('<plist')
                        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' + xml_content[xml_start:]

                    if xml_content.strip():
                        entitlements_data = plistlib.loads(xml_content.encode())
                        return entitlements_data
                    else:
                        return {}

                except Exception as e:
                    logger.debug(f"Error parsing entitlements XML: {e}")
                    return {}
            else:
                return {}

        except Exception as e:
            logger.debug(f"Error extracting entitlements: {e}")
            return {}

    def _extract_code_signing_info(self, app_path: str) -> Dict:
        """Extract detailed code signing information."""
        try:
            # Get basic signing info
            result = subprocess.run(
                [self.CODESIGN_PATH, '-dv', app_path],
                capture_output=True,
                text=True,
                check=False
            )

            code_info = {
                'signed': result.returncode == 0,
                'details': result.stderr if result.stderr else '',
                'bundle_id': '',
                'team_id': '',
                'format': '',
                'architectures': []
            }

            # Extract Bundle ID, Team ID, and Format from stderr output
            for line in result.stderr.splitlines():
                if line.startswith('Identifier='):
                    code_info['bundle_id'] = line.replace('Identifier=', '')
                elif self.TEAM_IDENTIFIER_PREFIX in line:
                    code_info['team_id'] = line.split(self.TEAM_IDENTIFIER_PREFIX)[1].strip()
                elif line.startswith('Format='):
                    code_info['format'] = line.replace('Format=', '')
                    # Extract architectures from Format line
                    code_info['architectures'] = self._parse_architectures_from_format(code_info['format'])

            return code_info

        except Exception as e:
            logger.error(f"Error extracting code signing info: {e}")
            return {}

    def _parse_architectures_from_format(self, format_string: str) -> List[str]:
        """
        Parse architecture information from the Format field.

        Examples:
            'app bundle with Mach-O thin (x86_64)' -> ['x86_64']
            'app bundle with Mach-O universal (x86_64 arm64)' -> ['x86_64', 'arm64']
            'app bundle with Mach-O universal (x86_64 arm64e)' -> ['x86_64', 'arm64e']
            'app bundle with Mach-O thin (arm64)' -> ['arm64']

        Args:
            format_string: The Format string from codesign output

        Returns:
            List of architectures found in the format string
        """
        architectures = []

        if not format_string:
            return architectures

        # Look for architecture information in parentheses
        import re
        match = re.search(r'\(([^)]+)\)', format_string)
        if match:
            arch_string = match.group(1)
            # Split by whitespace to get individual architectures
            architectures = arch_string.split()
            logger.debug(f"Extracted architectures from format '{format_string}': {architectures}")

        return architectures

    def _check_rosetta_required_from_architecture(self, architectures: List[str]) -> Dict:
        """
        Determine if Rosetta 2 is required based on architectures.

        Rosetta 2 is required on Apple Silicon (arm64) Macs if:
        - The app only has x86_64 or i386 architectures
        - The app does NOT include arm64 or arm64e architectures

        Args:
            architectures: List of architectures from codesign Format field

        Returns:
            Dictionary with Rosetta requirement information
        """
        rosetta_info = {
            'requires_rosetta': False,
            'detection_method': 'architecture',
            'detection_supported': True,
            'architectures': architectures,
            'rosetta_reason': None
        }

        if not architectures:
            rosetta_info['detection_supported'] = False
            rosetta_info['rosetta_reason'] = 'No architecture information available'
            return rosetta_info

        # Check if any ARM architectures are present
        has_arm = any(arch in ['arm64', 'arm64e', 'arm64_32'] for arch in architectures)
        has_intel = any(arch in ['x86_64', 'i386'] for arch in architectures)

        if has_arm:
            # Has ARM support - runs natively on Apple Silicon
            rosetta_info['requires_rosetta'] = False
            if has_intel:
                rosetta_info['rosetta_reason'] = f'Universal binary with native Apple Silicon support ({" ".join(architectures)})'
            else:
                rosetta_info['rosetta_reason'] = f'Native Apple Silicon binary ({" ".join(architectures)})'
        elif has_intel:
            # Only Intel architectures - requires Rosetta 2 on Apple Silicon
            rosetta_info['requires_rosetta'] = True
            rosetta_info['rosetta_reason'] = f'Intel-only binary ({" ".join(architectures)}) - requires Rosetta 2 on Apple Silicon'
        else:
            # Unknown architecture
            rosetta_info['detection_supported'] = False
            rosetta_info['rosetta_reason'] = f'Unknown architectures: {" ".join(architectures)}'

        return rosetta_info

    def _extract_embedded_profile(self, app_path: str) -> Dict:
        """Extract and analyze embedded provisioning profile if present."""
        profile_path = os.path.join(app_path, 'Contents', 'embedded.mobileprovision')

        if not os.path.exists(profile_path):
            return {}

        try:
            # Extract the provisioning profile using security command
            result = subprocess.run(
                ['/usr/bin/security', 'cms', '-D', '-i', profile_path],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                logger.warning(f"Failed to extract embedded profile: {result.stderr}")
                return {}

            # Parse the profile data
            profile_data = plistlib.loads(result.stdout.encode())

            # Extract relevant information
            entitlements = profile_data.get('Entitlements', {})
            provisioned_devices = profile_data.get('ProvisionedDevices', [])
            team_id = profile_data.get('TeamIdentifier', [''])[0]

            return {
                'has_embedded_profile': True,
                'entitlements': entitlements,
                'provisioned_devices': provisioned_devices,
                'team_id': team_id,
                'creation_date': profile_data.get('CreationDate'),
                'expiration_date': profile_data.get('ExpirationDate')
            }

        except Exception as e:
            logger.error(f"Error extracting embedded profile: {e}")
            return {}

    def _check_rosetta_requirements(self, code_signing_info: Dict) -> Dict:
        """
        Check if an application requires Rosetta to run on Apple Silicon.

        Also checks architecture compatibility on Intel systems and warns if
        an ARM-only app is detected (which won't run on Intel).

        Uses architecture information from codesign Format field as the primary
        detection method, with system_profiler as a fallback for runtime detection.

        Args:
            code_signing_info: Code signing information containing bundle_id and architectures

        Returns:
            Dictionary containing Rosetta usage information
        """
        rosetta_info = {
            'requires_rosetta': False,
            'has_native_version': True,
            'rosetta_override': None,
            'rosetta_reason': None,
            'detection_method': None,
            'detection_supported': False
        }

        # Check system architecture
        import platform
        system_arch = platform.machine()
        is_apple_silicon = system_arch == 'arm64'

        # Always check architecture from codesign Format field
        architectures = code_signing_info.get('architectures', [])
        if architectures:
            # Check if any ARM architectures are present
            has_arm = any(arch in ['arm64', 'arm64e', 'arm64_32'] for arch in architectures)
            has_intel = any(arch in ['x86_64', 'i386'] for arch in architectures)

            if is_apple_silicon:
                # Apple Silicon system - check if Rosetta is required
                arch_info = self._check_rosetta_required_from_architecture(architectures)
                rosetta_info.update(arch_info)
                logger.debug(f"Architecture-based Rosetta detection: {arch_info['rosetta_reason']}")
            else:
                # Intel system - check if app will run
                rosetta_info['detection_method'] = 'architecture'
                rosetta_info['detection_supported'] = True
                rosetta_info['architectures'] = architectures

                if has_arm and not has_intel:
                    # ARM-only app on Intel system - won't run!
                    rosetta_info['requires_rosetta'] = False  # Rosetta doesn't apply on Intel
                    rosetta_info['rosetta_reason'] = f'⚠️  ARM-only binary ({" ".join(architectures)}) - will NOT run on Intel systems'
                    logger.warning(f"ARM-only app detected on Intel system: {' '.join(architectures)}")
                elif has_intel:
                    if has_arm:
                        rosetta_info['rosetta_reason'] = f'Universal binary ({" ".join(architectures)}) - runs on both Intel and Apple Silicon'
                    else:
                        rosetta_info['rosetta_reason'] = f'Intel binary ({" ".join(architectures)}) - runs natively on Intel, requires Rosetta 2 on Apple Silicon'
                else:
                    rosetta_info['rosetta_reason'] = f'Unknown architectures: {" ".join(architectures)}'

                logger.debug(f"Architecture check on Intel system: {rosetta_info['rosetta_reason']}")

            return rosetta_info

        # No architecture information available
        if not is_apple_silicon:
            logger.debug(f"Intel system detected ({system_arch}) - no architecture information available")
            rosetta_info['detection_method'] = 'intel_system_no_arch_info'
            return rosetta_info

        # Apple Silicon - fallback: Try system_profiler for runtime detection
        bundle_id = code_signing_info.get('bundle_id', '')
        if not bundle_id:
            logger.debug("No bundle ID or architecture information available for Rosetta detection")
            rosetta_info['detection_method'] = 'no_bundle_id_or_architecture'
            return rosetta_info

        try:
            # Check if system_profiler supports Rosetta information (macOS 26+)
            result = subprocess.run(
                ['system_profiler', 'SPRosettaDataType', '-xml'],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                logger.debug("SPRosettaDataType not supported on this macOS version")
                rosetta_info['detection_method'] = 'system_profiler_unavailable'
                return rosetta_info

            rosetta_info['detection_supported'] = True
            rosetta_info['detection_method'] = 'system_profiler'

            # Parse the XML output
            import plistlib
            rosetta_data = plistlib.loads(result.stdout.encode())

            # Look through all Rosetta entries for our bundle ID
            for item in rosetta_data:
                for rosetta_item in item.get('_items', []):
                    for developer in rosetta_item.get('_items', []):
                        for app_entry in developer.get('_items', []):
                            # Check both primary and responsible bundle IDs
                            primary_bundle_id = app_entry.get('primary_process_bundle_id', '')
                            responsible_bundle_id = app_entry.get('responsible_bundle_id', '')

                            if bundle_id == primary_bundle_id or bundle_id == responsible_bundle_id:
                                rosetta_info['requires_rosetta'] = True
                                rosetta_info['has_native_version'] = app_entry.get('has_native_version', True)
                                rosetta_info['rosetta_reason'] = app_entry.get('rosetta_fallback_reason', '')
                                rosetta_info['rosetta_override'] = app_entry.get('rosetta_override_type', '')

                                logger.info(f"🔍 Rosetta info for {bundle_id}:")
                                logger.info(f"  - Requires Rosetta: {rosetta_info['requires_rosetta']}")
                                logger.info(f"  - Has Native Version: {rosetta_info['has_native_version']}")
                                if rosetta_info['rosetta_reason']:
                                    logger.info(f"  - Reason: {rosetta_info['rosetta_reason']}")
                                if rosetta_info['rosetta_override']:
                                    logger.info(f"  - Override Type: {rosetta_info['rosetta_override']}")

                                return rosetta_info

            # Bundle ID not found in Rosetta data - likely runs natively
            logger.debug(f"Bundle ID {bundle_id} not found in Rosetta data - likely native")
            rosetta_info['requires_rosetta'] = False

        except Exception as e:
            logger.error(f"Error checking Rosetta requirements: {e}")
            rosetta_info['detection_method'] = 'error'

        return rosetta_info

    def _analyze_frameworks(self, app_path: str) -> List[str]:
        """Analyze linked frameworks to detect usage patterns."""
        executable_path = self._find_main_executable(app_path)

        if not executable_path:
            return []

        try:
            result = subprocess.run(
                ['/usr/bin/otool', '-L', executable_path],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                logger.warning(f"Failed to analyze frameworks: {result.stderr}")
                return []

            frameworks = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if '.framework' in line:
                    # Extract framework name
                    framework_path = line.split('(')[0].strip()
                    framework_name = os.path.basename(framework_path)
                    frameworks.append(framework_name)

            return frameworks

        except Exception as e:
            logger.error(f"Error analyzing frameworks: {e}")
            return []

    def _find_main_executable(self, app_path: str) -> Optional[str]:
        """Find the main executable of the application."""
        info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')

        if not os.path.exists(info_plist_path):
            return None

        try:
            with open(info_plist_path, 'rb') as f:
                info = plistlib.load(f)

            executable_name = info.get('CFBundleExecutable')
            if executable_name:
                executable_path = os.path.join(app_path, 'Contents', 'MacOS', executable_name)
                if os.path.exists(executable_path):
                    return executable_path

        except Exception as e:
            logger.error(f"Error finding main executable: {e}")

        return None

    def _detect_pppc_requirements(self, analysis_results: Dict, all_entitlements: Dict) -> List[Dict]:
        """Detect PPPC (Privacy Preferences Policy Control) requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile

        Returns:
            List of PPPC requirement dictionaries
        """
        pppc = []
        pppc_found = []

        # Check for PPPC requirements (only allowable permissions)
        for entitlement, service in self.ALLOWABLE_PPPC_ENTITLEMENTS.items():
            if entitlement in all_entitlements:
                pppc_found.append(entitlement)
                pppc.append({
                    'service': service,
                    'entitlement': entitlement,
                    'bundle_id': analysis_results.get('code_signing', {}).get('bundle_id', ''),
                    'team_id': analysis_results.get('code_signing', {}).get('team_id', '')
                })

        if pppc_found:
            logger.info(f"  ✅ PPPC entitlements found: {pppc_found}")
        else:
            logger.debug("  - No PPPC entitlements found")

        # Enhanced detection based on frameworks and patterns (not hardcoded apps)
        bundle_id = analysis_results.get('code_signing', {}).get('bundle_id', '')
        team_id = analysis_results.get('code_signing', {}).get('team_id', '')
        bundle_info = analysis_results.get('bundle_info', {})
        frameworks = analysis_results.get('frameworks', [])

        # Check Info.plist for additional PPPC indicators
        info_plist_pppc = self._check_info_plist_for_pppc(bundle_info, bundle_id, team_id)
        if info_plist_pppc:
            pppc.extend(info_plist_pppc)
            logger.info(f"  ✅ Info.plist PPPC indicators found: {[req['service'] for req in info_plist_pppc]}")

        # Detect requirements based on linked frameworks and patterns
        framework_based_pppc = self._get_framework_based_pppc_requirements(analysis_results, frameworks)
        if framework_based_pppc:
            pppc.extend(framework_based_pppc)
            logger.info(f"  ✅ Framework-based PPPC requirements added: {[req['service'] for req in framework_based_pppc]}")

        # Heuristic detection: Apps with AppleEvents often need Accessibility to control UI elements
        # This catches automation apps that need to control other apps' interfaces
        has_apple_events = (
            'NSAppleEventsUsageDescription' in bundle_info
            or self.ENTITLEMENT_APPLE_EVENTS in all_entitlements
        )
        has_accessibility = any(req['service'] == 'Accessibility' for req in pppc)

        if has_apple_events and not has_accessibility:
            pppc.append({
                'service': 'Accessibility',
                'entitlement': 'heuristic-apple-events-accessibility',
                'bundle_id': bundle_id,
                'team_id': team_id,
                'detection_reason': 'Apps with AppleEvents typically need Accessibility to control UI elements'
            })
            logger.info("  ✅ Accessibility likely needed (heuristic: AppleEvents permission detected)")

        # Deduplicate PPPC requirements within this single app to prevent duplicate arrays in profiles
        if pppc:
            seen_services = set()
            deduplicated_pppc = []

            for req in pppc:
                # Create a unique key based on service, bundle_id, and team_id
                service_key = (req['service'], req['bundle_id'], req['team_id'])
                if service_key not in seen_services:
                    seen_services.add(service_key)
                    deduplicated_pppc.append(req)
                else:
                    logger.debug(f"  🔄 Deduplicating {req['service']} service for {req['bundle_id']} (same app detected via multiple methods)")

            pppc = deduplicated_pppc
            logger.info(f"  ✅ PPPC requirements after deduplication: {[req['service'] for req in pppc]}")

        # Warn if no PPPC requirements detected but Info.plist or frameworks suggest the app might need some
        if not pppc and (frameworks or bundle_info):
            app_name = os.path.basename(analysis_results.get('app_path', ''))
            warning_msg = f"No PPPC requirements detected - consider manual review of {app_name} for potential privacy permissions"
            logger.warning(f"  ⚠️  {warning_msg}")
            analysis_results['manual_review_warnings'].append({
                'type': 'pppc',
                'message': warning_msg,
                'app_name': app_name
            })

        return pppc

    def _detect_notification_requirements(self, analysis_results: Dict, all_entitlements: Dict, frameworks: List[str]) -> bool:
        """Detect notification requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile
            frameworks: List of linked frameworks

        Returns:
            True if notification requirements detected, False otherwise
        """
        bundle_info = analysis_results.get('bundle_info', {})

        # Check for notifications (UserNotifications framework, notification entitlements, or Info.plist keys)
        notification_indicators = [
            'UserNotifications.framework' in frameworks,
            'com.apple.developer.usernotifications.communication' in all_entitlements,
            'com.apple.developer.usernotifications.time-sensitive' in all_entitlements
        ]

        # Check Info.plist for notification-related keys
        info_plist_notification_indicators = self._check_info_plist_for_notifications(bundle_info)
        if info_plist_notification_indicators:
            notification_indicators.extend(info_plist_notification_indicators)
            logger.info(f"  ✅ Info.plist notification indicators found: {info_plist_notification_indicators}")

        # Heuristic detection: Apps with media permissions or automation often send notifications
        # Check for usage description keys that suggest interactive apps that likely send notifications
        if not any(notification_indicators):
            notification_usage_keys = [
                'NSCameraUsageDescription',
                'NSMicrophoneUsageDescription',
                'NSAppleEventsUsageDescription',
                'NSLocationWhenInUseUsageDescription',
                'NSLocationAlwaysUsageDescription',
                'NSCalendarsUsageDescription',
                'NSRemindersUsageDescription'
            ]

            for key in notification_usage_keys:
                if key in bundle_info:
                    notification_indicators.append(True)
                    logger.info(f"  ✅ Notification likely needed (heuristic: {key} suggests interactive app)")
                    break

        if any(notification_indicators):
            logger.info("  ✅ Notification requirements detected")
            return True
        else:
            logger.debug("  - No notification requirements found")
            return False

    def _check_network_extension_entitlements(self, all_entitlements: Dict, analysis_results: Dict) -> tuple:
        """Check for network extension entitlements that can be system extensions."""
        system_extensions = []
        system_ext_found = []

        network_ext_entitlement = all_entitlements.get(self.ENTITLEMENT_NETWORK_EXTENSION)
        if not network_ext_entitlement:
            return system_extensions, system_ext_found

        code_signing = analysis_results.get('code_signing', {})

        if isinstance(network_ext_entitlement, list):
            system_ext_types = [
                'packet-tunnel-provider-systemextension',
                'app-proxy-provider-systemextension',
                'dns-proxy-systemextension'
            ]
            found_system_types = [t for t in system_ext_types if t in network_ext_entitlement]
            if found_system_types:
                system_ext_found.append(f'{self.ENTITLEMENT_NETWORK_EXTENSION}: {found_system_types}')
                system_extensions.append({
                    'entitlement': self.ENTITLEMENT_NETWORK_EXTENSION,
                    'capabilities': found_system_types,
                    'team_id': code_signing.get('team_id', ''),
                    'bundle_id': code_signing.get('bundle_id', '')
                })
        else:
            system_ext_found.append(self.ENTITLEMENT_NETWORK_EXTENSION)
            system_extensions.append({
                'entitlement': self.ENTITLEMENT_NETWORK_EXTENSION,
                'team_id': code_signing.get('team_id', ''),
                'bundle_id': code_signing.get('bundle_id', '')
            })

        return system_extensions, system_ext_found

    def _apply_framework_fallback(self, system_extensions: List, frameworks: List[str], analysis_results: Dict) -> List[Dict]:
        """Apply framework-based fallback detection for system extensions."""
        if system_extensions:
            return system_extensions

        system_ext_detected = self._detect_system_extension_capability(frameworks)
        if system_ext_detected:
            logger.info(f"  ✅ System extension capability detected via frameworks: {system_ext_detected}")
            code_signing = analysis_results.get('code_signing', {})
            return [{
                'entitlement': 'framework-detected',
                'detection_method': system_ext_detected,
                'team_id': code_signing.get('team_id', ''),
                'bundle_id': code_signing.get('bundle_id', '')
            }]
        return []

    def _apply_systemctl_fallback(self, system_extensions: List, analysis_results: Dict) -> List[Dict]:
        """Apply systemextensionsctl fallback detection."""
        if system_extensions:
            return system_extensions

        code_signing = analysis_results.get('code_signing', {})
        system_ext_found_via_ctl = self._detect_system_extensions_via_systemctl(
            code_signing.get('team_id', ''),
            code_signing.get('bundle_id', '')
        )

        if system_ext_found_via_ctl:
            logger.info(f"  ✅ System extensions detected via systemextensionsctl: {len(system_ext_found_via_ctl)} found")
            result = []
            for ext_info in system_ext_found_via_ctl:
                result.append({
                    'entitlement': 'systemctl-detected',
                    'detection_method': ext_info['detection_method'],
                    'extension_bundle_id': ext_info['bundle_id'],
                    'extension_type': ext_info['extension_type'],
                    'team_id': ext_info['team_id'],
                    'bundle_id': code_signing.get('bundle_id', '')
                })
            return result
        return []

    def _detect_system_extension_requirements(self, analysis_results: Dict, all_entitlements: Dict, frameworks: List[str]) -> List[Dict]:
        """Detect system extension requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile
            frameworks: List of linked frameworks

        Returns:
            List of system extension requirement dictionaries
        """
        system_extensions = []
        system_ext_found = []
        app_path = analysis_results.get('app_path', '')
        code_signing = analysis_results.get('code_signing', {})

        logger.info("🔍 DEBUG: Checking for system extensions in entitlements")
        logger.info(f"🔍 DEBUG: Looking for '{self.ENTITLEMENT_SYSTEM_EXT_INSTALL}'")
        logger.info(f"🔍 DEBUG: Looking for '{self.ENTITLEMENT_NETWORK_EXTENSION}'")

        # Check for system extension install entitlement
        if self.ENTITLEMENT_SYSTEM_EXT_INSTALL in all_entitlements:
            system_ext_found.append(self.ENTITLEMENT_SYSTEM_EXT_INSTALL)
            system_extensions.append({
                'entitlement': self.ENTITLEMENT_SYSTEM_EXT_INSTALL,
                'team_id': code_signing.get('team_id', ''),
                'bundle_id': code_signing.get('bundle_id', '')
            })

        # Check for networking extensions
        net_exts, net_found = self._check_network_extension_entitlements(all_entitlements, analysis_results)
        system_extensions.extend(net_exts)
        system_ext_found.extend(net_found)

        # Check for other system extension entitlements
        for entitlement in self.SYSTEM_EXTENSION_ENTITLEMENTS:
            if entitlement in all_entitlements and entitlement != self.ENTITLEMENT_NETWORK_EXTENSION:
                system_ext_found.append(entitlement)
                system_extensions.append({
                    'entitlement': entitlement,
                    'team_id': code_signing.get('team_id', ''),
                    'bundle_id': code_signing.get('bundle_id', '')
                })

        if system_ext_found:
            logger.info(f"  ✅ System extension entitlements found: {system_ext_found}")
        else:
            logger.debug("  - No system extension entitlements found")

        # Apply fallback detection methods
        system_extensions = self._apply_framework_fallback(system_extensions, frameworks, analysis_results) or system_extensions
        system_extensions = self._apply_systemctl_fallback(system_extensions, analysis_results) or system_extensions

        # Look for system extensions within the app bundle
        if system_extensions:
            extension_data = self._find_system_extensions(app_path)
            if extension_data:
                analysis_results['system_extension_bundles'] = extension_data
                logger.info(f"  ✅ Found {len(extension_data)} system extension(s)")

        # Warn if no system extensions detected but frameworks suggest they might be needed
        if not system_extensions and frameworks:
            app_name = os.path.basename(app_path)
            warning_msg = f"No system extension requirements detected - consider manual review of {app_name} for potential system-level capabilities"
            logger.debug(f"  ⚠️  {warning_msg}")
            analysis_results['manual_review_warnings'].append({
                'type': 'system_extensions',
                'message': warning_msg,
                'app_name': app_name
            })

        return system_extensions

    def _detect_kernel_extension_requirements(self, analysis_results: Dict, all_entitlements: Dict) -> List[Dict]:
        """Detect kernel extension requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile

        Returns:
            List of kernel extension requirement dictionaries
        """
        kernel_extensions = []
        kernel_ext_found = []
        frameworks = analysis_results.get('frameworks', [])
        app_path = analysis_results.get('app_path', '')

        for entitlement in self.KERNEL_EXTENSION_IDENTIFIERS:
            if entitlement in all_entitlements:
                kernel_ext_found.append(entitlement)
                kernel_extensions.append({
                    'entitlement': entitlement,
                    'team_id': analysis_results.get('code_signing', {}).get('team_id', ''),
                    'bundle_id': analysis_results.get('code_signing', {}).get('bundle_id', '')
                })

        if kernel_ext_found:
            logger.info(f"  ✅ Kernel extension entitlements found: {kernel_ext_found}")
        else:
            logger.debug("  - No kernel extension entitlements found")

        # Warn if no kernel extensions detected but frameworks suggest they might be needed
        if not kernel_extensions and frameworks:
            app_name = os.path.basename(app_path)
            warning_msg = f"No kernel extension requirements detected - consider manual review of {app_name} for potential hardware/driver needs"
            logger.debug(f"  ⚠️  {warning_msg}")
            analysis_results['manual_review_warnings'].append({
                'type': 'kernel_extensions',
                'message': warning_msg,
                'app_name': app_name
            })

        return kernel_extensions

    def _detect_content_filter_requirements(self, analysis_results: Dict, all_entitlements: Dict, frameworks: List[str]) -> tuple:
        """Detect content filter requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile
            frameworks: List of linked frameworks

        Returns:
            Tuple of (is_required: bool, extension_data: List[Dict])
        """
        is_required = False
        extension_data = []
        content_filter_found = []
        app_path = analysis_results.get('app_path', '')

        # Check for networking extensions that can provide content filtering
        network_ext_entitlement = all_entitlements.get(self.ENTITLEMENT_NETWORK_EXTENSION)
        if network_ext_entitlement:
            # If it's an array, check for content filter types
            if isinstance(network_ext_entitlement, list):
                content_filter_types = [
                    'content-filter-provider-systemextension',
                    'content-filter-provider'
                ]

                found_filter_types = [t for t in content_filter_types if t in network_ext_entitlement]
                if found_filter_types:
                    content_filter_found.append(f'{self.ENTITLEMENT_NETWORK_EXTENSION}: {found_filter_types}')
                    is_required = True
            else:
                # If it's just a boolean true, treat as general content filter capability
                content_filter_found.append(self.ENTITLEMENT_NETWORK_EXTENSION)
                is_required = True

        # Check for other content filter entitlements
        for entitlement in self.CONTENT_FILTER_ENTITLEMENTS:
            if entitlement in all_entitlements and entitlement != self.ENTITLEMENT_NETWORK_EXTENSION:
                content_filter_found.append(entitlement)
                is_required = True

        if content_filter_found:
            logger.info(f"  ✅ Content filter entitlements found: {content_filter_found}")
        else:
            logger.debug("  - No content filter entitlements found")

        # Enhanced content filter detection based on frameworks and patterns
        if not is_required:
            logger.debug("  - No content filter entitlements found, checking framework-based detection")
            content_filter_detected = self._detect_content_filter_capability(frameworks)
            if content_filter_detected:
                is_required = True
                logger.info(f"  ✅ Content filter capability detected via frameworks: {content_filter_detected}")

        # Content filter detection using systemextensionsctl as final fallback
        if not is_required:
            content_filter_found_via_ctl = self._detect_content_filter_via_systemctl(
                analysis_results.get('code_signing', {}).get('team_id', ''),
                analysis_results.get('code_signing', {}).get('bundle_id', '')
            )
            if content_filter_found_via_ctl:
                is_required = True
                logger.info(f"  ✅ Content filter capability detected via systemextensionsctl: {content_filter_found_via_ctl}")

        # Look for content filter extensions within the app bundle
        if is_required:
            extension_data = self._find_content_filter_extensions(app_path)
            if extension_data:
                logger.info(f"  ✅ Found {len(extension_data)} content filter extension(s)")

        # Warn if no content filter detected but frameworks suggest it might be needed
        if not is_required and frameworks:
            app_name = os.path.basename(app_path)
            warning_msg = f"No content filter requirements detected - consider manual review of {app_name} for potential network filtering capabilities"
            logger.debug(f"  ⚠️  {warning_msg}")
            analysis_results['manual_review_warnings'].append({
                'type': 'content_filter',
                'message': warning_msg,
                'app_name': app_name
            })

        return (is_required, extension_data)

    def _detect_screen_recording_requirements(self, analysis_results: Dict, all_entitlements: Dict, frameworks: List[str]) -> bool:
        """Detect screen recording requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile
            frameworks: List of linked frameworks

        Returns:
            True if screen recording requirements detected, False otherwise
        """
        is_required = False
        screen_rec_found = []
        bundle_info = analysis_results.get('bundle_info', {})
        app_path = analysis_results.get('app_path', '')

        for entitlement in self.SCREEN_RECORDING_ENTITLEMENTS:
            if entitlement in all_entitlements:
                screen_rec_found.append(entitlement)
                is_required = True
                break

        # Check Info.plist for screen recording indicators
        if not is_required:
            info_plist_screen_rec = self._check_info_plist_for_screen_recording(bundle_info)
            if info_plist_screen_rec:
                is_required = True
                logger.info(f"  ✅ Info.plist screen recording indicators found: {info_plist_screen_rec}")

        # Enhanced screen recording detection based on frameworks
        if not is_required:
            screen_rec_frameworks = [
                'ScreenCaptureKit.framework',
                'ReplayKit.framework',
                'CoreGraphics.framework'  # Often used for screen capture
            ]

            for framework in frameworks:
                if framework in screen_rec_frameworks:
                    is_required = True
                    logger.info(f"  ✅ Screen recording framework detected: {framework}")
                    break

        # Heuristic detection: Apps with camera + microphone likely need screen recording
        # This catches collaboration/communication apps (video conferencing, remote support, etc.)
        if not is_required:
            has_camera = (
                'NSCameraUsageDescription' in bundle_info
                or 'com.apple.security.device.camera' in all_entitlements
            )
            has_microphone = (
                'NSMicrophoneUsageDescription' in bundle_info
                or 'com.apple.security.device.audio-input' in all_entitlements
            )

            # If app has BOTH camera AND microphone, very likely a communication app needing screen recording
            if has_camera and has_microphone:
                is_required = True
                logger.info("  ✅ Screen recording likely needed (heuristic: camera + microphone detected)")

        if screen_rec_found:
            logger.info(f"  ✅ Screen recording entitlements found: {screen_rec_found}")
        elif is_required:
            logger.info("  ✅ Screen recording requirements detected from framework/heuristic analysis")
        else:
            logger.debug("  - No screen recording entitlements found")

        # Warn if no screen recording detected but might be a communication app
        if not is_required and frameworks:
            app_name = os.path.basename(app_path)
            warning_msg = f"No screen recording requirements detected - consider manual review if {app_name} is a communication/video app"
            logger.debug(f"  ⚠️  {warning_msg}")
            analysis_results['manual_review_warnings'].append({
                'type': 'screen_recording',
                'message': warning_msg,
                'app_name': app_name
            })

        return is_required

    def _detect_login_item_requirements(self, analysis_results: Dict, all_entitlements: Dict) -> List[Dict]:
        """Detect login item requirements.

        Args:
            analysis_results: Complete analysis results dictionary
            all_entitlements: Combined entitlements from code signature and embedded profile

        Returns:
            List of login item requirement dictionaries
        """
        login_items = []
        login_items_found = []
        bundle_id = analysis_results.get('code_signing', {}).get('bundle_id', '')
        team_id = analysis_results.get('code_signing', {}).get('team_id', '')
        bundle_info = analysis_results.get('bundle_info', {})

        for entitlement in self.LOGIN_ITEMS_ENTITLEMENTS:
            if entitlement in all_entitlements:
                login_items_found.append(entitlement)
                login_items.append({
                    'entitlement': entitlement,
                    'bundle_id': bundle_id,
                    'team_id': team_id
                })

        # Check Info.plist for login item indicators
        info_plist_login_items = self._check_info_plist_for_login_items(bundle_info, bundle_id, team_id)
        if info_plist_login_items:
            login_items.extend(info_plist_login_items)
            logger.info("  ✅ Info.plist login item indicators found")

        if login_items_found:
            logger.info(f"  ✅ Login item entitlements found: {login_items_found}")
        elif info_plist_login_items:
            logger.info("  ✅ Login item requirements detected from Info.plist")
        else:
            logger.debug("  - No login item entitlements found")

        return login_items

    def _determine_required_profiles(self, analysis_results: Dict) -> Dict:
        """Determine which configuration profiles are required based on analysis."""
        required = {
            'pppc': [],
            'notifications': False,
            'system_extensions': [],
            'kernel_extensions': [],
            'content_filter': False,
            'screen_recording': False,
            'managed_login_items': []
        }

        # Extract analysis components
        entitlements = analysis_results.get('entitlements', {})
        embedded_entitlements = analysis_results.get('embedded_profile', {}).get('entitlements', {})
        frameworks = analysis_results.get('frameworks', [])
        app_path = analysis_results.get('app_path', '')
        app_name = analysis_results.get('app_name', 'Unknown')

        # Initial logging
        logger.debug(f"Analyzing requirements for {os.path.basename(app_path)}")
        logger.debug(f"Found {len(entitlements)} entitlements")
        logger.debug(f"Found {len(embedded_entitlements)} embedded entitlements")
        logger.debug(f"Found {len(frameworks)} frameworks")

        # Debug log entitlement keys for troubleshooting
        if embedded_entitlements:
            logger.info(f"🔍 Embedded entitlements keys: {list(embedded_entitlements.keys())}")
        if entitlements:
            logger.info(f"🔍 Code signature entitlements keys: {list(entitlements.keys())}")

        # Log what we're analyzing for debugging
        logger.debug(f"Analyzing {app_name} for configuration profile requirements:")
        logger.debug(f"  - Code signature entitlements: {len(entitlements)} found")
        logger.debug(f"  - Embedded profile entitlements: {len(embedded_entitlements)} found")
        logger.debug(f"  - Linked frameworks: {len(frameworks)} found")

        # Combine entitlements from code signature and embedded profile
        all_entitlements = {**entitlements, **embedded_entitlements}

        # Log all entitlements for debugging
        if all_entitlements:
            logger.debug(f"  - All entitlements found: {list(all_entitlements.keys())}")
            # Log specific entitlements we're looking for
            network_ext = all_entitlements.get(self.ENTITLEMENT_NETWORK_EXTENSION)
            if network_ext:
                logger.info(f"  🔍 Found networking entitlement: {network_ext}")

            sys_ext_install = all_entitlements.get(self.ENTITLEMENT_SYSTEM_EXT_INSTALL)
            if sys_ext_install:
                logger.info(f"  🔍 Found system extension install entitlement: {sys_ext_install}")
        else:
            logger.debug("  - No entitlements found")

        # Call helper methods to detect each profile type
        required['pppc'] = self._detect_pppc_requirements(analysis_results, all_entitlements)
        required['notifications'] = self._detect_notification_requirements(analysis_results, all_entitlements, frameworks)
        required['system_extensions'] = self._detect_system_extension_requirements(analysis_results, all_entitlements, frameworks)
        required['kernel_extensions'] = self._detect_kernel_extension_requirements(analysis_results, all_entitlements)

        content_filter_result = self._detect_content_filter_requirements(analysis_results, all_entitlements, frameworks)
        required['content_filter'] = content_filter_result[0]
        if content_filter_result[1]:  # extension_data
            required['content_filter_extensions'] = content_filter_result[1]

        required['screen_recording'] = self._detect_screen_recording_requirements(analysis_results, all_entitlements, frameworks)
        required['managed_login_items'] = self._detect_login_item_requirements(analysis_results, all_entitlements)

        # Summary logging
        total_profiles_needed = (
            len(required['pppc'])
            + (1 if required['notifications'] else 0)
            + len(required['system_extensions'])
            + len(required['kernel_extensions'])
            + (1 if required['content_filter'] else 0)
            + (1 if required['screen_recording'] else 0)
            + len(required['managed_login_items'])
        )

        if total_profiles_needed > 0:
            logger.info(f"  📋 Total configuration profiles needed: {total_profiles_needed}")
        else:
            logger.debug(f"  ℹ️  No configuration profiles needed for {app_name}")

        return required

    def _get_dragged_app_path(self) -> Optional[str]:
        """Get and validate dragged application path from user input."""
        print("\nDrag and drop an application here (or press Enter to finish):")
        app_path = input().strip()

        # Allow user to finish
        if not app_path:
            return None

        # Clean up the path - remove quotes and unescape shell-escaped characters
        # macOS terminal escapes special chars like |, &, (, ), etc. with backslashes
        import re
        app_path = app_path.strip('"').strip("'")  # Remove surrounding quotes
        app_path = re.sub(r'\\(.)', r'\1', app_path)  # Remove escape backslashes

        if not os.path.exists(app_path):
            print(f"❌ Error: Application not found at {app_path}")
            return ""  # Empty string signals to retry

        if not app_path.endswith('.app'):
            print(f"❌ Error: Not an application bundle: {app_path}")
            return ""  # Empty string signals to retry

        return app_path

    def _display_profile_requirements(self, required: Dict) -> bool:
        """Display detected profile requirements."""
        detected_any = False

        if required.get('pppc'):
            print(f"📋 PPPC Requirements: {len(required['pppc'])} detected")
            detected_any = True

        if required.get('notifications'):
            print("🔔 Notifications: Required")
            detected_any = True

        if required.get('system_extensions'):
            detected_any = True

        if required.get('kernel_extensions'):
            print(f"⚙️  Kernel Extensions: {len(required['kernel_extensions'])} detected")
            detected_any = True

        if required.get('content_filter'):
            print("🌐 Content Filter: Required")
            detected_any = True

        if required.get('screen_recording'):
            print("📺 Screen Recording: Required")
            detected_any = True

        if required.get('managed_login_items'):
            print(f"🚀 Managed Login Items: {len(required['managed_login_items'])} detected")
            detected_any = True

        if not detected_any:
            print("ℹ️  No configuration profile requirements detected")

        return detected_any

    def analyze_dragged_applications(self) -> List[Dict]:
        """
        Interactive method to allow user to drag and drop applications for analysis.

        Returns:
            List of analysis results for all dragged applications
        """
        print("\nConfiguration Profile Generation")
        print("================================")
        print("Drag and drop applications to analyze for configuration profile requirements.")
        print("This will detect PPPC, System Extensions, Notifications, and other requirements.")

        results = []

        while True:
            try:
                app_path = self._get_dragged_app_path()

                # None means user pressed Enter to finish
                if app_path is None:
                    break

                # Empty string means validation failed, retry
                if app_path == "":
                    continue

                print(f"\n🔍 Analyzing: {os.path.basename(app_path)}")
                print("-" * 50)

                analysis = self.analyze_application(app_path)

                if analysis.get('analysis_errors'):
                    print("⚠️  Analysis completed with errors:")
                    for error in analysis['analysis_errors']:
                        print(f"   - {error}")
                else:
                    print("✅ Analysis completed successfully")

                # Display detected requirements
                required = analysis.get('required_profiles', {})
                self._display_profile_requirements(required)

                results.append(analysis)

            except KeyboardInterrupt:
                print("\n\nAnalysis cancelled by user")
                break
            except Exception as e:
                print(f"❌ Error during analysis: {e}")
                logger.error(f"Error in analyze_dragged_applications: {e}")

        print(f"\n✅ Analysis complete. Processed {len(results)} applications.")
        return results

    def _get_framework_based_pppc_requirements(self, analysis_results: Dict, frameworks: List[str]) -> List[Dict]:
        """Detect PPPC requirements based on linked frameworks and capabilities."""
        requirements = []
        bundle_id = analysis_results.get('code_signing', {}).get('bundle_id', '')
        team_id = analysis_results.get('code_signing', {}).get('team_id', '')
        app_name = analysis_results.get('app_name', '')

        # Framework-based detection patterns
        framework_mappings = {
            # Media and Photos frameworks (Camera/Microphone excluded - PPPC can only deny these)
            'AVFoundation.framework': [],  # Removed Camera, Microphone - use PPPC deny instead
            'Photos.framework': ['Photos'],
            'PhotosUI.framework': ['Photos'],
            'CoreMedia.framework': [],  # Removed Camera, Microphone - use PPPC deny instead
            'VideoToolbox.framework': [],  # Removed Camera - use PPPC deny instead
            'CoreAudio.framework': [],  # Removed Microphone - use PPPC deny instead
            'AudioToolbox.framework': [],  # Removed Microphone - use PPPC deny instead

            # Communication frameworks (Camera/Microphone excluded - PPPC can only deny these)
            'CallKit.framework': [],  # Removed Microphone, Camera - use PPPC deny instead
            'WebRTC.framework': [],  # Removed Microphone, Camera - use PPPC deny instead
            'Network.framework': [],  # Removed Camera, Microphone - use PPPC deny instead

            # Location frameworks
            'CoreLocation.framework': ['Location'],
            'MapKit.framework': ['Location'],

            # Contacts and Calendar frameworks
            'Contacts.framework': ['AddressBook'],
            'ContactsUI.framework': ['AddressBook'],
            'EventKit.framework': ['Calendar'],
            'EventKitUI.framework': ['Calendar'],

            # Bluetooth frameworks
            'CoreBluetooth.framework': ['BluetoothAlways'],
            'IOBluetooth.framework': ['BluetoothAlways'],

            # File system frameworks (may need file access)
            'FileProvider.framework': ['SystemPolicyDocumentsFolder', 'SystemPolicyDesktopFolder'],
            'UniformTypeIdentifiers.framework': ['SystemPolicyDocumentsFolder'],

            # Screen capture frameworks - these should trigger Screen Recording profiles, not PPPC
            # 'ScreenCaptureKit.framework': ['ScreenCapture'],  # Removed - triggers Screen Recording profile
            # 'ReplayKit.framework': ['ScreenCapture'],          # Removed - triggers Screen Recording profile

            # Accessibility and Recognition frameworks
            'ApplicationServices.framework': ['Accessibility', 'PostEvent'],
            'CoreGraphics.framework': ['Accessibility', 'PostEvent'],
            'Speech.framework': ['SpeechRecognition'],
            'SpeechRecognition.framework': ['SpeechRecognition'],

            # System frameworks that may require various permissions
            'AppKit.framework': ['Accessibility', 'PostEvent', 'ListenEvent'],
            'Carbon.framework': ['PostEvent', 'ListenEvent'],
            'Cocoa.framework': ['Accessibility', 'PostEvent'],

            # Network and storage frameworks
            'NetFS.framework': ['SystemPolicyNetworkVolumes'],
            'DiskArbitration.framework': ['SystemPolicyRemovableVolumes'],
        }

        # Check each framework for potential PPPC requirements
        detected_services = set()
        for framework in frameworks:
            if framework in framework_mappings:
                for service in framework_mappings[framework]:
                    if service not in detected_services:
                        detected_services.add(service)
                        # Add AppleEvents receiver detection for automation frameworks
                        ae_receiver_data = self._detect_apple_events_receiver(bundle_id, app_name, service)

                        req_data = {
                            'service': service,
                            'entitlement': f'framework-detected-{framework}',
                            'bundle_id': bundle_id,
                            'team_id': team_id,
                            'detection_reason': f'Linked to {framework} which typically requires {service} access'
                        }

                        # Add receiver data if AppleEvents service
                        if ae_receiver_data:
                            req_data.update({
                                'ae_receiver_bundle_id': ae_receiver_data.get('bundle_id'),
                                'ae_receiver_team_id': ae_receiver_data.get('team_id'),
                                'ae_detection_reason': ae_receiver_data.get('detection_reason')
                            })

                        requirements.append(req_data)

        return requirements

    def _detect_content_filter_capability(self, frameworks: List[str]) -> Optional[str]:
        """Detect content filtering capability based on frameworks only."""
        # Framework-based detection (handle both .framework and bare framework names)
        content_filter_frameworks = [
            'NetworkExtension.framework', 'NetworkExtension',
            'Network.framework', 'Network',
            'SystemConfiguration.framework', 'SystemConfiguration'
        ]

        for framework in frameworks:
            if framework in content_filter_frameworks:
                return f"Framework-based ({framework})"

        return None

    def _detect_system_extension_capability(self, frameworks: List[str]) -> Optional[str]:
        """Detect system extension capability based on frameworks only."""
        # Framework-based detection (handle both .framework and bare framework names)
        system_ext_frameworks = [
            'NetworkExtension.framework', 'NetworkExtension',
            'EndpointSecurity.framework', 'EndpointSecurity',
            'SystemExtensions.framework', 'SystemExtensions',
            'DriverKit.framework', 'DriverKit'
        ]

        for framework in frameworks:
            if framework in system_ext_frameworks:
                return f"Framework-based ({framework})"

        return None

    def _detect_kernel_extension_capability(self, frameworks: List[str]) -> Optional[str]:
        """Detect kernel extension capability based on frameworks only."""
        # Framework-based detection
        kernel_ext_frameworks = [
            'IOKit.framework',
            'System.framework',
            'Kernel.framework'
        ]

        for framework in frameworks:
            if framework in kernel_ext_frameworks:
                return f"Framework-based ({framework})"

        return None

    def _find_content_filter_extensions(self, app_path: str) -> List[Dict]:
        """
        Find content filter extensions within an app bundle.

        Args:
            app_path: Path to the .app bundle

        Returns:
            List of extension information dictionaries
        """
        extensions = []

        # Look for extensions in Contents/Extensions and Contents/PlugIns
        extension_paths = [
            os.path.join(app_path, "Contents", "Extensions"),
            os.path.join(app_path, "Contents", "PlugIns")
        ]

        for ext_dir in extension_paths:
            if not os.path.exists(ext_dir):
                continue

            try:
                for item in os.listdir(ext_dir):
                    if item.endswith('.appex') or item.endswith(self.SYSTEM_EXTENSION_SUFFIX):
                        ext_path = os.path.join(ext_dir, item)
                        ext_info_path = os.path.join(ext_path, "Contents", "Info.plist")

                        if os.path.exists(ext_info_path):
                            try:
                                with open(ext_info_path, 'rb') as f:
                                    ext_info = plistlib.load(f)

                                ext_bundle_id = ext_info.get('CFBundleIdentifier', '')
                                ext_name = ext_info.get('CFBundleDisplayName', '') or ext_info.get('CFBundleName', '')
                                ext_point_id = ext_info.get('NSExtension', {}).get('NSExtensionPointIdentifier', '')

                                # Check if it's a content filter extension
                                if ('content-filter' in ext_point_id.lower()
                                        or 'network-extension' in ext_point_id.lower()
                                        or 'web-content-filter' in ext_point_id.lower()
                                        or 'filter' in ext_name.lower()
                                        or 'filter' in ext_bundle_id.lower()):

                                    extensions.append({
                                        'bundle_id': ext_bundle_id,
                                        'name': ext_name,
                                        'extension_point': ext_point_id,
                                        'path': ext_path,
                                        'type': 'content_filter'
                                    })
                                    logger.info(f"    Found content filter extension: {ext_bundle_id} ({ext_name})")

                            except Exception as e:
                                logger.debug(f"    Error reading extension Info.plist at {ext_info_path}: {e}")

            except Exception as e:
                logger.debug(f"  Error scanning extension directory {ext_dir}: {e}")

        return extensions

    def _find_system_extensions(self, app_path: str) -> List[Dict]:
        """
        Find system extensions within an app bundle.

        Args:
            app_path: Path to the .app bundle

        Returns:
            List of system extension information dictionaries
        """
        extensions = []

        # Look for system extensions in Contents/Library/SystemExtensions and other common paths
        extension_paths = [
            os.path.join(app_path, "Contents", "Library", "SystemExtensions"),
            os.path.join(app_path, "Contents", "Extensions"),
            os.path.join(app_path, "Contents", "PlugIns")
        ]

        for ext_dir in extension_paths:
            if not os.path.exists(ext_dir):
                continue

            try:
                for item in os.listdir(ext_dir):
                    if item.endswith(self.SYSTEM_EXTENSION_SUFFIX) or item.endswith('.appex'):
                        ext_path = os.path.join(ext_dir, item)
                        ext_info_path = os.path.join(ext_path, "Contents", "Info.plist")

                        if os.path.exists(ext_info_path):
                            try:
                                with open(ext_info_path, 'rb') as f:
                                    ext_info = plistlib.load(f)

                                ext_bundle_id = ext_info.get('CFBundleIdentifier', '')
                                ext_name = ext_info.get('CFBundleDisplayName', '') or ext_info.get('CFBundleName', '')
                                ext_point_id = ext_info.get('NSExtension', {}).get('NSExtensionPointIdentifier', '')

                                # Check if it's a system extension
                                if (item.endswith('.systemextension')
                                        or 'system-extension' in ext_point_id.lower()
                                        or 'endpoint-security' in ext_point_id.lower()
                                        or 'network-extension' in ext_point_id.lower()
                                        or 'driver' in ext_name.lower()
                                        or ext_info.get('NSExtension', {}).get('NSExtensionPointIdentifier') == 'com.apple.system-extension'):

                                    extensions.append({
                                        'bundle_id': ext_bundle_id,
                                        'name': ext_name,
                                        'extension_point': ext_point_id,
                                        'path': ext_path,
                                        'type': 'system_extension'
                                    })
                                    logger.info(f"    Found system extension: {ext_bundle_id} ({ext_name})")

                            except Exception as e:
                                logger.debug(f"    Error reading system extension Info.plist at {ext_info_path}: {e}")

            except Exception as e:
                logger.debug(f"  Error scanning extension directory {ext_dir}: {e}")

        return extensions

    def _check_info_plist_for_notifications(self, bundle_info: Dict) -> List[str]:
        """
        Check Info.plist for notification-related keys that indicate notification requirements.

        Args:
            bundle_info: Dictionary containing Info.plist data

        Returns:
            List of notification indicators found
        """
        indicators = []

        # Notification-related Info.plist keys
        notification_keys = [
            'NSUserNotificationAlertStyle',  # Chrome and others
            'NSUserNotificationDefaultSoundName',
            'NSUserNotificationsBadgeAppIconFlag',
            'NSUserNotificationsEnable',
            'NSSupportsAutomaticTermination',  # Often paired with notifications
            'LSUIElement',  # Background apps that might show notifications
        ]

        for key in notification_keys:
            if key in bundle_info:
                indicators.append(f"Info.plist key: {key}")
                logger.debug(f"Found notification indicator in Info.plist: {key} = {bundle_info[key]}")

        # Check for notification-related URL schemes
        url_schemes = bundle_info.get('CFBundleURLTypes', [])
        for url_type in url_schemes:
            schemes = url_type.get('CFBundleURLSchemes', [])
            for scheme in schemes:
                if any(notification_term in scheme.lower() for notification_term in ['notification', 'alert', 'badge']):
                    indicators.append(f"Notification URL scheme: {scheme}")

        return indicators

    def _check_info_plist_for_pppc(self, bundle_info: Dict, bundle_id: str, team_id: str) -> List[Dict]:
        """
        Check Info.plist for keys that indicate PPPC requirements.

        Args:
            bundle_info: Dictionary containing Info.plist data
            bundle_id: Application bundle identifier
            team_id: Application team identifier

        Returns:
            List of PPPC requirement dictionaries
        """
        requirements = []

        # Info.plist keys that indicate specific PPPC needs
        pppc_indicators = {
            # Camera/Microphone indicators removed - PPPC can only deny these, not allow
            # 'NSCameraUsageDescription': 'Camera',  # Use PPPC deny instead
            # 'NSMicrophoneUsageDescription': 'Microphone',  # Use PPPC deny instead

            # Location indicators
            'NSLocationUsageDescription': 'Location',
            'NSLocationWhenInUseUsageDescription': 'Location',
            'NSLocationAlwaysUsageDescription': 'Location',
            'NSLocationAlwaysAndWhenInUseUsageDescription': 'Location',

            # Contacts/Calendar indicators
            'NSContactsUsageDescription': 'AddressBook',
            'NSCalendarsUsageDescription': 'Calendar',
            'NSRemindersUsageDescription': 'Reminders',

            # Photos indicators
            'NSPhotoLibraryUsageDescription': 'Photos',
            'NSPhotoLibraryAddUsageDescription': 'Photos',

            # Bluetooth indicators
            'NSBluetoothUsageDescription': 'BluetoothAlways',
            'NSBluetoothAlwaysUsageDescription': 'BluetoothAlways',
            'NSBluetoothPeripheralUsageDescription': 'BluetoothAlways',

            # File access indicators
            'NSDesktopFolderUsageDescription': 'SystemPolicyDesktopFolder',
            'NSDocumentsFolderUsageDescription': 'SystemPolicyDocumentsFolder',
            'NSDownloadsFolderUsageDescription': 'SystemPolicyDownloadsFolder',
            'NSRemovableVolumesUsageDescription': 'SystemPolicyRemovableVolumes',
            'NSNetworkVolumesUsageDescription': 'SystemPolicyNetworkVolumes',

            # Apple Events/Automation indicators
            'NSAppleEventsUsageDescription': 'AppleEvents',
            'NSAppleScriptEnabled': 'AppleEvents',

            # Recognition indicators
            'NSSpeechRecognitionUsageDescription': 'SpeechRecognition',

            # System policy indicators
            'NSSystemAdministrationUsageDescription': 'SystemPolicySysAdminFiles',
        }

        for plist_key, service in pppc_indicators.items():
            if plist_key in bundle_info:
                logger.debug(f"Found PPPC indicator in Info.plist: {plist_key} = {bundle_info[plist_key]}")

                req_data = {
                    'service': service,
                    'entitlement': f'info-plist-{plist_key}',
                    'bundle_id': bundle_id,
                    'team_id': team_id,
                    'detection_reason': f'Info.plist contains {plist_key} indicating {service} access'
                }

                # Add AppleEvents receiver detection if this is an AppleEvents service
                if service == 'AppleEvents':
                    ae_receiver_data = self._detect_apple_events_receiver(bundle_id, os.path.basename(bundle_id), service)
                    if ae_receiver_data:
                        req_data.update({
                            'ae_receiver_bundle_id': ae_receiver_data.get('bundle_id'),
                            'ae_receiver_team_id': ae_receiver_data.get('team_id'),
                            'ae_detection_reason': ae_receiver_data.get('detection_reason')
                        })

                requirements.append(req_data)

        return requirements

    def _check_info_plist_for_screen_recording(self, bundle_info: Dict) -> List[str]:
        """
        Check Info.plist for screen recording indicators.

        Args:
            bundle_info: Dictionary containing Info.plist data

        Returns:
            List of screen recording indicators found
        """
        indicators = []

        # Screen recording related Info.plist keys
        screen_recording_keys = [
            'NSScreenCaptureDescription',
            'NSScreenRecordingUsageDescription',
            'CGWindowListOption',
            'NSSystemAdministrationUsageDescription'  # Sometimes used for screen access
        ]

        for key in screen_recording_keys:
            if key in bundle_info:
                indicators.append(f"Info.plist key: {key}")
                logger.debug(f"Found screen recording indicator in Info.plist: {key} = {bundle_info[key]}")

        return indicators

    def _check_info_plist_for_login_items(self, bundle_info: Dict, bundle_id: str, team_id: str) -> List[Dict]:
        """
        Check Info.plist for login item/background app indicators.

        Args:
            bundle_info: Dictionary containing Info.plist data
            bundle_id: Application bundle identifier
            team_id: Application team identifier

        Returns:
            List of login item requirement dictionaries
        """
        requirements = []

        # Login item indicators
        login_item_indicators = {
            'LSUIElement': 'Background app (no dock icon)',
            'LSBackgroundOnly': 'Background only app',
            'NSSupportsAutomaticTermination': 'Supports automatic termination'
        }

        for key, description in login_item_indicators.items():
            if key in bundle_info and bundle_info[key]:
                requirements.append({
                    'entitlement': f'info-plist-{key}',
                    'bundle_id': bundle_id,
                    'team_id': team_id,
                    'detection_reason': f'Info.plist contains {key}: {description}'
                })
                logger.debug(f"Found login item indicator in Info.plist: {key} = {bundle_info[key]}")

        # Check for SMPrivilegedExecutables (privileged helper tools)
        sm_privileged_executables = bundle_info.get('SMPrivilegedExecutables', {})
        if sm_privileged_executables:
            logger.debug(f"Found SMPrivilegedExecutables in Info.plist: {list(sm_privileged_executables.keys())}")
            for helper_bundle_id, code_requirement in sm_privileged_executables.items():
                # Extract team ID from code requirement if possible
                helper_team_id = self._extract_team_id_from_code_requirement(code_requirement)

                requirements.append({
                    'entitlement': f'sm-privileged-executable-{helper_bundle_id}',
                    'bundle_id': helper_bundle_id,
                    'team_id': helper_team_id or team_id,  # Use extracted team ID or fall back to main app's team ID
                    'detection_reason': f'SMPrivilegedExecutables contains privileged helper: {helper_bundle_id}',
                    'code_requirement': code_requirement,
                    'is_privileged_helper': True
                })
                logger.info(f"Found privileged helper in SMPrivilegedExecutables: {helper_bundle_id}")

        return requirements

    def _extract_team_id_from_code_requirement(self, code_requirement: str) -> str:
        """
        Extract team ID from a code requirement string.

        Args:
            code_requirement: Code requirement string from SMPrivilegedExecutables

        Returns:
            Team ID if found, empty string otherwise
        """
        try:
            import re
            # Look for patterns like: certificate leaf[subject.OU] = "TEAMID123"
            team_id_pattern = r'certificate leaf\[subject\.OU\]\s*=\s*["\']([^"\']+)["\']'
            match = re.search(team_id_pattern, code_requirement)
            if match:
                return match.group(1)

            # Alternative pattern: subject.OU] = TEAMID123 (without quotes)
            team_id_pattern_alt = r'subject\.OU\]\s*=\s*([A-Z0-9]+)'
            match = re.search(team_id_pattern_alt, code_requirement)
            if match:
                return match.group(1)

        except Exception as e:
            logger.debug(f"Error extracting team ID from code requirement: {e}")

        return ''

    def _parse_btm_identifier(self, btm_identifier: str) -> str:
        """
        Parse BTM identifier to extract actual bundle identifier.

        BTM identifiers can be in formats like:
        - "2.com.splice.Splice" -> "com.splice.Splice"
        - "com.splice.Splice" -> "com.splice.Splice"
        - "1.com.example.app" -> "com.example.app"

        Args:
            btm_identifier: The identifier from BTM output

        Returns:
            The actual bundle identifier without BTM prefixes
        """
        if not btm_identifier:
            return ''

        # Check if it starts with a number followed by a dot
        # This is BTM's internal tracking format
        if '.' in btm_identifier:
            parts = btm_identifier.split('.', 1)
            if len(parts) == 2 and parts[0].isdigit():
                # Remove the numeric prefix (e.g., "2.com.splice.Splice" -> "com.splice.Splice")
                return parts[1]

        # If no numeric prefix found, return as-is
        return btm_identifier

    def _parse_btm_line(self, line: str, current_item_data: Dict) -> None:
        """Parse a BTM data line and update current_item_data."""
        if ':' not in line:
            return

        key, value = line.split(':', 1)
        key = key.strip().lower().replace(' ', '_')
        value = value.strip()

        if key == 'identifier':
            current_item_data['identifier'] = value
        elif key == 'bundle_identifier':
            current_item_data['bundle_identifier'] = value
        elif key == 'name':
            current_item_data['name'] = value
        elif key == 'type':
            current_item_data['type'] = value
        elif key == 'disposition':
            current_item_data['disposition'] = value
        elif key == 'executable_path':
            current_item_data['executable_path'] = value
        elif key == 'is_managed':
            current_item_data['is_managed'] = 'Yes' in value
        elif key == 'team_identifier':
            current_item_data['team_id'] = value
        elif key == 'parent_identifier':
            current_item_data['parent_identifier'] = value
        elif key == 'developer_name':
            # Sometimes team ID is in developer name field
            if '(' in value and ')' in value:
                team_match = value.split('(')[-1].replace(')', '').strip()
                if len(team_match) == 10 and team_match.isupper():
                    current_item_data['team_id'] = team_match

    def _create_login_item_dict(self, item_data: Dict) -> Dict:
        """Create a login item dictionary from BTM item data."""
        btm_identifier = item_data.get('identifier', '')
        parsed_bundle_id = self._parse_btm_identifier(btm_identifier)
        bundle_id_value = item_data.get('bundle_identifier', parsed_bundle_id)

        return {
            'bundle_id': bundle_id_value,
            'btm_identifier': btm_identifier,
            'identifier': btm_identifier,
            'name': item_data.get('name', ''),
            'type': item_data.get('type', 'Login Item'),
            'enabled': item_data.get('disposition', '') != 'Disabled',
            'source': 'system_btm_data',
            'is_managed': item_data.get('is_managed', False),
            'executable_path': item_data.get('executable_path', ''),
            'team_id': item_data.get('team_id', '')
        }

    def _save_login_item_if_relevant(self, item_data: Dict, bundle_id: str, login_items: List,
                                       team_id: str = None, app_name: str = None) -> None:
        """Save login item if it's relevant and has an identifier."""
        if not item_data.get('identifier'):
            return

        if self._is_relevant_login_item(item_data, bundle_id, team_id=team_id, app_name=app_name):
            login_items.append(self._create_login_item_dict(item_data))

    def get_login_items_from_system_data(self, btm_data: str, bundle_id: str = None,
                                          team_id: str = None, app_name: str = None) -> List[Dict]:
        """
        Extract Login Items from existing BTM system data (already captured by system checks).
        This leverages the data already captured by the main testing workflow.

        Args:
            btm_data: BTM output data already captured by system checks
            bundle_id: Optional bundle ID to filter results
            team_id: Optional team identifier to match
            app_name: Optional application name for matching

        Returns:
            List of Login Item dictionaries
        """
        logger.info(f"Extracting Login Items from existing system data "
                    f"(bundle_id={bundle_id}, team_id={team_id}, app_name={app_name})")

        login_items = []

        if not btm_data:
            logger.debug("No BTM data provided")
            return login_items

        try:
            # Parse the existing BTM data
            current_item = None
            current_item_data = {}

            for line in btm_data.split('\n'):
                line = line.strip()

                # Look for item numbers like "#1:", "#2:", etc.
                if line.startswith('#') and line.endswith(':') and len(line) < 10:
                    # Save previous item if it exists and matches our criteria
                    if current_item:
                        self._save_login_item_if_relevant(
                            current_item_data, bundle_id, login_items,
                            team_id=team_id, app_name=app_name
                        )

                    # Start new item
                    current_item = line
                    current_item_data = {'item_number': line}

                elif current_item:
                    # Parse key-value pairs
                    self._parse_btm_line(line, current_item_data)

            # Don't forget the last item
            if current_item:
                self._save_login_item_if_relevant(
                    current_item_data, bundle_id, login_items,
                    team_id=team_id, app_name=app_name
                )

            logger.info(f"Extracted {len(login_items)} relevant Login Items from system data")
            for idx, item in enumerate(login_items, 1):
                print(f"  {idx}. bundle_id={item.get('bundle_id')}, team_id={item.get('team_id')}, type={item.get('type')}")

        except Exception as e:
            logger.error(f"Error parsing BTM system data: {e}")

        return login_items

    def _is_relevant_login_item(self, item_data: Dict, bundle_id: str = None,
                                  team_id: str = None, app_name: str = None) -> bool:
        """
        Check if a Login Item is relevant to the current application.

        Uses multiple matching strategies: bundle_id substring, team_id match,
        app name in paths/names, and parent_identifier matching.

        Args:
            item_data: Login Item data dictionary
            bundle_id: Optional bundle ID to filter by
            team_id: Optional team identifier to match
            app_name: Optional application name (e.g. 'ScanSnapHomeMain')

        Returns:
            True if the item is relevant
        """
        if not bundle_id and not team_id and not app_name:
            return True

        identifier = item_data.get('identifier', '').lower()
        name = item_data.get('name', '').lower()
        path = item_data.get('executable_path', '').lower()
        parent_id = item_data.get('parent_identifier', '').lower()
        item_team_id = item_data.get('team_id', '').lower()

        # 1. Match on full bundle_id substring
        if bundle_id:
            bundle_id_lower = bundle_id.lower()
            if (bundle_id_lower in identifier
                    or bundle_id_lower in name
                    or bundle_id_lower in path):
                return True

        # 2. Match on team_id (most reliable for third-party apps)
        if team_id and item_team_id:
            if team_id.lower() == item_team_id:
                return True
            # Also check parent_identifier's developer name which may contain the team_id
            if team_id.lower() in parent_id:
                return True

        # 3. Match on app name in executable path or item name
        if app_name:
            app_name_lower = app_name.lower().replace('.app', '')
            if (app_name_lower in path
                    or app_name_lower in name
                    or app_name_lower in identifier):
                return True

        return False

    def get_launch_items_from_system_data(self, initial_items: set, current_items: set,
                                           bundle_id: str = None, team_id: str = None,
                                           app_name: str = None) -> List[Dict]:
        """
        Extract Launch Agents/Daemons from existing system comparison data.
        This leverages the data already captured by the system comparison workflow.

        Args:
            initial_items: Set of initial launch items
            current_items: Set of current launch items
            bundle_id: Optional bundle ID to filter results
            team_id: Optional team identifier to match
            app_name: Optional application name for matching

        Returns:
            List of Launch Agent/Daemon dictionaries
        """
        logger.info("Extracting Launch items from existing system comparison data")

        launch_items = []

        # Find new items added after installation
        new_items = current_items - initial_items

        for item in new_items:
            # Accept all new items when no filter is specified
            # Otherwise, include items that match any of our identifiers
            if bundle_id or team_id or app_name:
                item_lower = item.lower()
                matched = False
                if bundle_id and bundle_id.lower() in item_lower:
                    matched = True
                if app_name and app_name.lower().replace('.app', '') in item_lower:
                    matched = True
                # Note: team_id won't appear in the plist filename, but we accept
                # all new items and try to verify team_id from plist contents below
                if not matched and team_id:
                    # Can't filter by team_id from filename alone; accept and verify below
                    matched = True
                if not matched:
                    continue

            # Parse the item string (format: "LaunchDaemon: filename.plist" or "LaunchAgent: filename.plist")
            if ':' in item:
                item_type, filename = item.split(':', 1)
                item_type = item_type.strip()
                filename = filename.strip()

                # Extract bundle ID from filename (usually the filename without .plist)
                item_bundle_id = filename.replace(self.PLIST_SUFFIX, '')

                # Extract exact label from the plist file
                exact_label = self._extract_label_from_launch_item(item_type, filename)

                # Try to extract team ID from the actual plist file if it exists
                item_team_id = self._extract_team_id_from_launch_item(item_type, filename)

                # If we only matched on team_id (not filename), verify the extracted
                # team_id from the plist actually matches
                if team_id and not matched:
                    # This was matched only because team_id was provided
                    if item_team_id and item_team_id.lower() != team_id.lower():
                        continue

                # Determine path based on item type
                if item_type in ['LaunchDaemon', 'LaunchAgent']:
                    item_path = f"/Library/{item_type}s/{filename}"
                elif item_type == 'UserLaunchAgent':
                    item_path = f"~/Library/LaunchAgents/{filename}"
                else:
                    item_path = ''

                launch_items.append({
                    'bundle_id': item_bundle_id,
                    'exact_label': exact_label,  # Add exact label
                    'label_prefix': exact_label.split('.')[0] if exact_label else '',  # First part for prefix matching
                    'filename': filename,
                    'type': item_type,
                    'source': 'system_comparison_data',
                    'path': item_path,
                    'team_id': item_team_id
                })

        return launch_items

    def _extract_team_id_from_launch_item(self, item_type: str, filename: str) -> str:
        """
        Extract team ID from a launch daemon/agent plist file.

        Args:
            item_type: Type of launch item (LaunchDaemon, LaunchAgent, UserLaunchAgent)
            filename: Filename of the plist

        Returns:
            Team ID if found, empty string otherwise
        """
        try:
            # Construct the path to the plist file
            if item_type == 'LaunchDaemon':
                plist_path = f"/Library/LaunchDaemons/{filename}"
            elif item_type == 'LaunchAgent':
                plist_path = f"/Library/LaunchAgents/{filename}"
            elif item_type == 'UserLaunchAgent':
                plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{filename}")
            else:
                return ''

            # Try to read the plist file
            if os.path.exists(plist_path):
                import plistlib
                with open(plist_path, 'rb') as f:
                    plist_data = plistlib.load(f)

                # Look for team ID in common locations
                program_arguments = plist_data.get('ProgramArguments', [])
                program = plist_data.get('Program', '')

                # Check if the program points to an app bundle
                for arg in program_arguments + [program]:
                    if isinstance(arg, str) and arg.endswith('.app/Contents/MacOS/'):
                        # Extract team ID from the app bundle
                        app_path = arg.replace('/Contents/MacOS/', '').rstrip('/')
                        if app_path.endswith('.app'):
                            return self._get_team_id_from_app(app_path)

        except Exception as e:
            logger.debug(f"Could not extract team ID from {filename}: {e}")

        return ''

    def _extract_label_from_launch_item(self, item_type: str, filename: str) -> str:
        """
        Extract the exact Label from a launch daemon/agent plist file.

        Args:
            item_type: Type of launch item (LaunchDaemon, LaunchAgent, UserLaunchAgent)
            filename: Filename of the plist

        Returns:
            Exact label if found, empty string otherwise
        """
        try:
            # Construct the path to the plist file
            if item_type == 'LaunchDaemon':
                plist_path = f"/Library/LaunchDaemons/{filename}"
            elif item_type == 'LaunchAgent':
                plist_path = f"/Library/LaunchAgents/{filename}"
            elif item_type == 'UserLaunchAgent':
                plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{filename}")
            else:
                return ''

            # Try to read the plist file
            if os.path.exists(plist_path):
                import plistlib
                with open(plist_path, 'rb') as f:
                    plist_data = plistlib.load(f)

                # Extract the exact Label from the plist
                label = plist_data.get('Label', '')
                if label:
                    logger.info(f"Extracted exact label '{label}' from {item_type} {filename}")
                    return label
                else:
                    # Fallback: use filename without .plist extension as label
                    fallback_label = filename.replace(self.PLIST_SUFFIX, '')
                    logger.info(f"No Label key found in {filename}, using filename as label: {fallback_label}")
                    return fallback_label

        except Exception as e:
            logger.error(f"Error extracting label from {item_type} {filename}: {e}")
            # Fallback: use filename without .plist extension
            return filename.replace(self.PLIST_SUFFIX, '')

        return ''

    def _get_team_id_from_app(self, app_path: str) -> str:
        """
        Extract team ID from an application bundle.

        Args:
            app_path: Path to the .app bundle

        Returns:
            Team ID if found, empty string otherwise
        """
        try:
            import subprocess
            result = subprocess.run(
                [self.CODESIGN_PATH, '-dv', app_path],
                capture_output=True,
                text=True,
                check=False
            )

            # Extract Team ID from stderr output
            for line in result.stderr.splitlines():
                if line.startswith(self.TEAM_IDENTIFIER_PREFIX):
                    return line.split('=', 1)[1].strip()

        except Exception as e:
            logger.debug(f"Could not extract team ID from {app_path}: {e}")

        return ''

    def _detect_apple_events_receiver(self, bundle_id: str, app_name: str, service: str) -> Dict[str, str]:
        """
        Dynamically detect AppleEvents receiver applications based on app patterns and capabilities.

        Args:
            bundle_id: Bundle ID of the app requesting AppleEvents access
            app_name: Name of the app requesting AppleEvents access
            service: The PPPC service being requested

        Returns:
            Dictionary with receiver bundle_id and team_id if detected
        """
        if service != 'AppleEvents':
            return {}

        # Dynamic detection based on app categories and patterns
        receivers = self._get_dynamic_apple_events_receivers(bundle_id, app_name)

        return receivers

    def _get_dynamic_apple_events_receivers(self, bundle_id: str, app_name: str) -> Dict[str, str]:
        """
        Dynamically determine likely AppleEvents receiver apps based on the requesting app's category.

        Args:
            bundle_id: Bundle ID of the app requesting AppleEvents access
            app_name: Name of the app requesting AppleEvents access

        Returns:
            Dictionary with receiver bundle_id and team_id if detected
        """
        bundle_id_lower = bundle_id.lower()
        app_name_lower = app_name.lower()

        # Development tools often control Terminal, TextEdit, or Finder
        dev_patterns = ['code', 'xcode', 'git', 'terminal', 'editor', 'ide', 'developer', 'script', 'vim', 'emacs', 'bbedit', 'text']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in dev_patterns):
            return {
                'bundle_id': 'com.apple.terminal',
                'team_id': '',
                'detection_reason': 'Development/Text editor - commonly controls Terminal for tools and scripts'
            }

        # Web browsers often control various productivity apps or system apps
        browser_patterns = ['chrome', 'firefox', 'safari', 'edge', 'browser', 'webkit']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in browser_patterns):
            return {
                'bundle_id': 'com.apple.finder',
                'team_id': '',
                'detection_reason': 'Web browser - commonly controls Finder for file operations'
            }

        # Media/Creative apps often control other media apps or system media controls
        media_patterns = ['adobe', 'photo', 'video', 'audio', 'creative', 'editor', 'media', 'music', 'spotify', 'itunes']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in media_patterns):
            return {
                'bundle_id': 'com.apple.music',
                'team_id': '',
                'detection_reason': 'Media/Creative app - commonly controls Music or media applications'
            }

        # Communication apps might control Calendar, Contacts, or other productivity apps
        comm_patterns = ['teams', 'zoom', 'meet', 'skype', 'discord', 'slack', 'webex', 'call', 'conference', 'mail', 'calendar']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in comm_patterns):
            return {
                'bundle_id': 'com.apple.calendar',
                'team_id': '',
                'detection_reason': 'Communication app - commonly controls Calendar for scheduling'
            }

        # Automation/Productivity tools often control various system apps
        automation_patterns = ['automation', 'workflow', 'macro', 'script', 'productivity', 'utility', 'launcher']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in automation_patterns):
            return {
                'bundle_id': 'com.apple.systempreferences',
                'team_id': '',
                'detection_reason': 'Automation/Productivity tool - commonly controls System Preferences'
            }

        # Security/System tools often control system applications
        security_patterns = ['security', 'antivirus', 'firewall', 'cleaner', 'monitor', 'system', 'admin']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in security_patterns):
            return {
                'bundle_id': 'com.apple.systempreferences',
                'team_id': '',
                'detection_reason': 'Security/System tool - commonly controls System Preferences'
            }

        # Backup/Sync tools often control Finder for file operations
        backup_patterns = ['backup', 'sync', 'cloud', 'drive', 'dropbox', 'onedrive', 'icloud']
        if any(pattern in bundle_id_lower or pattern in app_name_lower for pattern in backup_patterns):
            return {
                'bundle_id': 'com.apple.finder',
                'team_id': '',
                'detection_reason': 'Backup/Sync tool - commonly controls Finder for file operations'
            }

        # Default fallback - show warning instead of generating generic receiver
        return {
            'bundle_id': '',
            'team_id': '',
            'detection_reason': 'AppleEvents receiver cannot be determined automatically - manual review recommended'
        }

    def _detect_system_extensions_via_systemctl(self, team_id: str, bundle_id: str) -> List[Dict]:
        """
        Detect system extensions using systemextensionsctl list command.

        Args:
            team_id: The team ID of the application being analyzed
            bundle_id: The bundle ID of the application being analyzed

        Returns:
            List of detected system extension information
        """
        try:
            import subprocess
            result = subprocess.run(
                ['/usr/bin/systemextensionsctl', 'list'],
                capture_output=True,
                text=True,
                check=False
            )

            if result.returncode != 0:
                logger.debug(f"systemextensionsctl failed: {result.stderr}")
                return []

            extensions_found = []
            output_lines = result.stdout.split('\n')

            current_category = None
            for line in output_lines:
                line = line.strip()

                # Track current extension category
                if line.startswith('--- com.apple.system_extension.'):
                    current_category = line.split('---')[1].strip().split()[0]
                    continue

                # Skip header lines and empty lines
                if not line or line.startswith('enabled') or line.startswith('*'):
                    if line.startswith('*') and '\t' in line:
                        # This is an extension entry
                        parts = line.split('\t')
                        if len(parts) >= 4:
                            try:
                                ext_team_id = parts[2].strip()
                                ext_bundle_info = parts[3].strip()
                                ext_bundle_id = ext_bundle_info.split()[0] if ext_bundle_info else ''

                                # Check if this extension belongs to our app by team ID
                                if team_id and ext_team_id == team_id:
                                    extensions_found.append({
                                        'team_id': ext_team_id,
                                        'bundle_id': ext_bundle_id,
                                        'extension_type': current_category or 'unknown',
                                        'detection_method': f"systemextensionsctl (team ID match: {ext_team_id})"
                                    })
                                    logger.debug(f"Found system extension via teamID: {ext_bundle_id} ({current_category})")

                                # Also check by bundle ID prefix (for extensions that are part of the app)
                                elif bundle_id and ext_bundle_id.startswith(bundle_id.replace('.app', '')):
                                    extensions_found.append({
                                        'team_id': ext_team_id,
                                        'bundle_id': ext_bundle_id,
                                        'extension_type': current_category or 'unknown',
                                        'detection_method': f"systemextensionsctl (bundle ID match: {ext_bundle_id})"
                                    })
                                    logger.debug(f"Found system extension via bundleID: {ext_bundle_id} ({current_category})")

                            except (IndexError, ValueError) as e:
                                logger.debug(f"Error parsing systemextensionsctl line: {line} - {e}")
                                continue
                    continue

            return extensions_found

        except Exception as e:
            logger.debug(f"Error running systemextensionsctl: {e}")
            return []

    def _detect_content_filter_via_systemctl(self, team_id: str, bundle_id: str) -> Optional[str]:
        """
        Detect content filter capability using systemextensionsctl list command.

        Args:
            team_id: The team ID of the application being analyzed
            bundle_id: The bundle ID of the application being analyzed

        Returns:
            Detection method string if content filter found, None otherwise
        """
        extensions = self._detect_system_extensions_via_systemctl(team_id, bundle_id)

        # Check if any found extensions are network extensions (which can provide content filtering)
        for ext in extensions:
            if ext['extension_type'] == 'com.apple.system_extension.network_extension':
                return f"systemextensionsctl (network extension: {ext['bundle_id']})"

        return None
