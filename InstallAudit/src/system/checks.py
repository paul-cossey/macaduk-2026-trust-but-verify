# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
System checking methods for InstallAudit.
"""

import subprocess
import platform
import os
import plistlib
import logging

from .notifications import NotificationChecker
from ..core.exceptions import SystemCheckError, ConfigurationError

logger = logging.getLogger(__name__)


class SystemChecker(NotificationChecker):
    """Handles system information gathering and checks."""

    # Constants for duplicated string literals
    MODEL_UNKNOWN = "- Model Identifier: Unknown"
    MACOS_UNKNOWN = "macOS (Unknown)"
    INFO_PLIST = "Info.plist"
    UNKNOWN_VERSION = "Unknown Version"

    def __init__(self):
        """Initialize SystemChecker with instance variables."""
        self.initial_sysext = None
        self.initial_btm = None
        self.initial_notifications = None

    def _get_system_info(self):
        """Gather comprehensive system information"""
        try:
            print("\nGathering system information...")

            # Get macOS version with marketing name using sw_vers
            try:
                os_ver = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
            except subprocess.CalledProcessError:
                # Fallback to platform method if sw_vers fails
                os_ver = platform.mac_ver()[0]

            marketing_name = self._get_macos_marketing_name(os_ver)
            full_os_info = f"{os_ver} ({marketing_name})" if marketing_name else os_ver
            print(f"- Detected macOS version: {full_os_info}")

            # Get architecture
            arch = platform.machine()
            print(f"- Detected architecture: {arch}")

            # Get Munki version
            try:
                munki_ver = subprocess.check_output(
                    ["/usr/local/munki/managedsoftwareupdate", "--version"],
                    text=True
                ).strip()
                print(f"- Detected Munki version: {munki_ver}")
            except subprocess.CalledProcessError:
                munki_ver = "Unknown"
                print("- Unable to determine Munki version")

            # Get current console user
            console_user = self._get_console_user()
            print(f"- Console user: {console_user}")

            # Check if user is admin
            user_admin_status = self._check_user_admin_status(console_user)
            print(f"- User admin status: {user_admin_status}")

            # Get hardware model identifier
            try:
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0:
                    model_identifier, model_name = self._extract_hardware_model(result.stdout)
                    if model_identifier:
                        print(f"- Model Identifier: {model_identifier}")
                    else:
                        print(self.MODEL_UNKNOWN)
                else:
                    print(self.MODEL_UNKNOWN)
                    model_identifier, model_name = None, None
            except Exception:
                print(self.MODEL_UNKNOWN)
                model_identifier, model_name = None, None

            # Check if system is virtual machine or hardware
            system_type = self._detect_system_type(model_name)
            print(f"- System type: {system_type}")

            # Get serial number
            serial_number = self._get_serial_number()
            print(f"- Serial number: {serial_number}")

            # Get security tool versions
            security_tool_versions = self._get_security_tool_versions()
            print(f"- Security tools detected: {len(security_tool_versions)} tools")

            # Get XProtect status
            xprotect_status = self._get_xprotect_status()
            if "error" not in xprotect_status:
                print(f"- XProtect status: Launch scans: {xprotect_status.get('launch_scans', 'unknown')}, "
                      f"Background scans: {xprotect_status.get('background_scans', 'unknown')}")

            return {
                "os_version": os_ver,
                "os_marketing_name": marketing_name,
                "os_version_full": full_os_info,
                "architecture": arch,
                "munki_version": munki_ver,
                "console_user": console_user,
                "user_admin_status": user_admin_status,
                "model_identifier": model_identifier,
                "system_type": system_type,
                "serial_number": serial_number,
                "security_tool_versions": security_tool_versions,
                "xprotect_status": xprotect_status
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            print(f"❌ Error gathering system information: {e}")
            return {"error": str(e)}

    def _run_system_checks(self):
        try:
            print("\nRunning pre-installation system checks")
            print("=" * 60)

            # Check system extensions
            print("Checking system extensions...")
            sysext_result = subprocess.run(
                ["systemextensionsctl", "list"],
                capture_output=True,
                text=True
            )
            self.initial_sysext = sysext_result.stdout.strip()
            print("✅ System extensions check completed")

            # Check managed login items
            print("Checking managed login items...")
            btm_result = subprocess.run(
                ["sfltool", "dumpbtm"],
                capture_output=True,
                text=True
            )
            self.initial_btm = btm_result.stdout.strip()

            # Also capture initial launch daemon/agent files
            def get_initial_launch_items():
                """Get initial launch daemon and agent files"""
                items = set()
                try:
                    # Check LaunchDaemons
                    daemon_result = subprocess.run(["ls", "/Library/LaunchDaemons/"],
                                                   capture_output=True, text=True)
                    if daemon_result.returncode == 0:
                        for item in daemon_result.stdout.strip().split('\n'):
                            if item.endswith('.plist'):
                                items.add(f"LaunchDaemon: {item}")

                    # Check LaunchAgents
                    agent_result = subprocess.run(["ls", "/Library/LaunchAgents/"],
                                                  capture_output=True, text=True)
                    if agent_result.returncode == 0:
                        for item in agent_result.stdout.strip().split('\n'):
                            if item.endswith('.plist'):
                                items.add(f"LaunchAgent: {item}")
                except Exception:
                    pass
                return items

            self.initial_launch_items = get_initial_launch_items()
            print("✅ Managed login items check completed")

            # Check notifications database
            print("Checking notifications database...")

            # Get macOS version to set expectations
            try:
                # Use sw_vers to get accurate macOS version
                os_ver = subprocess.check_output(["sw_vers", "-productVersion"], text=True).strip()
                major_version = int(os_ver.split('.')[0]) if os_ver else 0

                if major_version >= 26:
                    print(f"   Running on macOS {os_ver} - authorization restrictions expected")

            except (ValueError, IndexError, subprocess.CalledProcessError):
                pass  # Continue without version warning if parsing fails

            self.initial_notifications = self._check_notifications_db()
            print("✅ Notifications database check completed")

            return True
        except Exception as e:
            logger.error(f"Error running system checks: {e}")
            print(f"❌ Error running system checks: {e}")
            return False

    def _check_munki_status(self):
        """Verify Munki service status and configuration"""
        try:
            # Check Munki service status
            result = subprocess.run(
                ["/usr/local/munki/managedsoftwareupdate", "--version"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise SystemCheckError("Munki service not responding")

            # Verify Munki configuration
            managed_installs_dir = "/Library/Managed Installs"
            required_files = [
                "ManagedInstallReport.plist",
                "manifests",
                "catalogs"
            ]

            for file in required_files:
                path = os.path.join(managed_installs_dir, file)
                if not os.path.exists(path):
                    raise SystemCheckError(f"Required Munki file not found: {file}")

            # Check Munki preferences
            try:
                with open(
                    "/Library/Preferences/ManagedInstalls.plist", "rb"
                ) as f:
                    prefs = plistlib.load(f)
                if not prefs.get("SoftwareRepoURL"):
                    raise ConfigurationError("Munki software repo URL not configured")
            except (OSError, plistlib.InvalidFileException) as e:
                raise ConfigurationError(f"Error reading Munki preferences: {e}")

            return True
        except Exception as e:
            logger.error(f"Munki status check failed: {e}")
            return False

    def _get_console_user(self):
        """Get the current console user"""
        try:
            result = subprocess.run(
                ["/usr/bin/stat", "-f", "%Su", "/dev/console"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "Unknown"

    def _check_user_admin_status(self, username):
        """Check if the specified user has admin privileges"""
        if not username or username == "Unknown":
            return "Unknown"

        try:
            result = subprocess.run(
                ["dseditgroup", "-o", "checkmember", "-m", username, "admin"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return "Administrator"
            else:
                return "Standard User"
        except subprocess.CalledProcessError:
            return "Unknown"

    def _detect_system_type(self, provided_model_name=None):
        """Detect if system is running on actual hardware or a virtual machine"""
        try:
            # Check system_profiler for hardware information
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                hardware_info = result.stdout.lower()
                hardware_raw = result.stdout  # Keep original case for model extraction

                # Extract hardware model from output or use provided model name
                if provided_model_name:
                    # Use the model name already extracted in the main method
                    display_model = provided_model_name
                else:
                    # Extract model info for fallback
                    model_identifier, model_name = self._extract_hardware_model(hardware_raw)
                    display_model = model_name or model_identifier

                # Check for common VM identifiers
                vm_indicators = [
                    "vmware",
                    "virtualbox",
                    "parallels",
                    "qemu",
                    "microsoft corporation",  # Hyper-V
                    "innotek gmbh",          # VirtualBox
                    "apple virtualization"   # Apple's virtualization framework
                ]

                for indicator in vm_indicators:
                    if indicator in hardware_info:
                        vm_type = f"Virtual Machine ({indicator.title()})"
                        if display_model:
                            vm_type += f" - {display_model}"

                        # Print warning when VM is detected
                        print("\n⚠️  WARNING: Virtual Machine Detected")
                        print("   Some software may not install or work correctly on virtual machines.")
                        print("   Malware often detects VMs and may remain dormant during testing.")
                        print("   Consider testing on a dedicated physical test computer for more")
                        print("   accurate results, especially when testing security software.\n")
                        return vm_type

                # If no VM indicators found, likely physical hardware
                physical_type = "Physical Hardware"
                if display_model:
                    physical_type += f" - {display_model}"

                return physical_type
            else:
                return "Unknown"

        except subprocess.CalledProcessError:
            return "Unknown"

    def _get_serial_number(self):
        """Get the system serial number"""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Serial Number' in line:
                        # Extract serial number from line like "Serial Number (system): ABC123DEF456"
                        parts = line.split(':')
                        if len(parts) > 1:
                            return parts[1].strip()

                # Fallback method using ioreg
                result = subprocess.run(
                    ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'IOPlatformSerialNumber' in line:
                            # Extract from line like '"IOPlatformSerialNumber" = "ABC123DEF456"'
                            parts = line.split('=')
                            if len(parts) > 1:
                                serial = parts[1].strip().strip('"')
                                return serial

            return "Unknown"

        except subprocess.CalledProcessError:
            return "Unknown"

    def _get_security_tool_versions(self):
        """Get version information for detected security tools"""
        security_tools = {}

        # List of security tools to check with their detection methods
        tools_to_check = {
            "BlockBlock": {
                "app_path": "/Applications/BlockBlock Helper.app",
                "bundle_path": "/Library/Application Support/Objective-See/BlockBlock",
                "process_name": "BlockBlock Helper"
            },
            "LuLu": {
                "app_path": "/Applications/LuLu.app",
                "bundle_path": "/Library/Application Support/Objective-See/LuLu",
                "process_name": "LuLu"
            },
            "ReiKey": {
                "app_path": "/Applications/ReiKey.app",
                "bundle_path": "/Library/Application Support/Objective-See/ReiKey",
                "process_name": "ReiKey"
            },
            "RansomWhere": {
                "app_path": "/Applications/RansomWhere Helper.app",
                "alt_app_path": "/Library/Objective-See/RansomWhere/RansomWhere.app",
                "bundle_path": "/Library/Application Support/Objective-See/RansomWhere",
                "binary_path": "/Library/Objective-See/RansomWhere/RansomWhere",
                "process_name": "RansomWhere"
            },
            "OverSight": {
                "app_path": "/Applications/OverSight.app",
                "bundle_path": "/Library/Application Support/Objective-See/OverSight",
                "process_name": "OverSight"
            },
            "XProtect": {
                "bundle_path": "/System/Library/CoreServices/XProtect.bundle",
                "alt_bundle_path": "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
                "process_name": "XProtect"
            },
            "KnockKnock": {
                "app_path": "/Applications/KnockKnock.app",
                "bundle_path": "/Library/Application Support/Objective-See/KnockKnock",
                "process_name": "KnockKnock"
            }
        }

        for tool_name, paths in tools_to_check.items():
            version = self._get_tool_version(tool_name, paths)
            if version != "Not Installed":
                security_tools[tool_name] = version

        return security_tools

    def _get_xprotect_version(self):
        """Get XProtect version using xprotect command."""
        try:
            result = subprocess.run(
                ["sudo", "xprotect", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                import re
                version_match = re.search(r'Version:\s*(\d+)', result.stdout)
                date_match = re.search(r'Installed:\s*([0-9-]+\s+[0-9:]+)', result.stdout)

                if version_match:
                    version = version_match.group(1)
                    if date_match:
                        date = date_match.group(1)
                        return f"{version} (Installed: {date})"
                    return f"{version} (System)"

            return "System Component (Version check failed)"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return "System Component (Version check failed)"

    def _get_ransomwhere_version(self, paths):
        """Get RansomWhere version from Info.plist."""
        # Check primary app location first
        app_path = paths.get("app_path")
        if app_path and os.path.exists(app_path):
            version = self._get_version_from_info_plist(app_path)
            if version:
                return version

        # Check alternative app location
        alt_app_path = paths.get("alt_app_path")
        if alt_app_path and os.path.exists(alt_app_path):
            version = self._get_version_from_info_plist(alt_app_path)
            if version:
                return version

        # If Info.plist checks fail but binary exists, indicate it's installed
        binary_path = paths.get("binary_path")
        if binary_path and os.path.exists(binary_path):
            return "Installed (Version Unknown)"

        return None

    def _get_version_from_info_plist(self, app_path):
        """Extract version from Info.plist in an app bundle."""
        info_plist_path = os.path.join(app_path, "Contents", self.INFO_PLIST)
        if os.path.exists(info_plist_path):
            try:
                with open(info_plist_path, 'rb') as f:
                    plist_data = plistlib.load(f)
                version = plist_data.get('CFBundleShortVersionString', self.UNKNOWN_VERSION)
                return f"{version} (Application)"
            except Exception:
                pass
        return None

    def _check_bundle_or_process(self, paths):
        """Check if bundle exists or process is running."""
        # Try to check if bundle/helper exists
        bundle_path = paths.get("bundle_path")
        if bundle_path and os.path.exists(bundle_path):
            return "Installed (Version Unknown)"

        # Check if process is running
        process_name = paths.get("process_name")
        if process_name:
            try:
                result = subprocess.run(
                    ["pgrep", "-f", process_name],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip():
                    return "Running (Version Unknown)"
            except subprocess.CalledProcessError:
                pass

        return "Not Installed"

    def _get_tool_version(self, tool_name, paths):
        """Get version for a specific security tool"""
        try:
            # Special handling for XProtect version extraction
            if tool_name == "XProtect":
                return self._get_xprotect_version()

            # Special handling for RansomWhere version extraction
            if tool_name == "RansomWhere":
                version = self._get_ransomwhere_version(paths)
                if version:
                    return version

            # Try to get version from app bundle Info.plist
            app_path = paths.get("app_path")
            if app_path and os.path.exists(app_path):
                version = self._get_version_from_info_plist(app_path)
                if version:
                    return version

            # Check bundle path or process
            return self._check_bundle_or_process(paths)

        except Exception as e:
            logger.error(f"Error getting version for {tool_name}: {e}")
            return "Unknown"

    def _get_xprotect_status(self):
        """Get XProtect status information including scan settings"""
        try:
            result = subprocess.run(
                ["sudo", "xprotect", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                status_info = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'launch scans:' in line.lower():
                        status_info['launch_scans'] = 'enabled' if 'enabled' in line.lower() else 'disabled'
                    elif 'background scans:' in line.lower():
                        status_info['background_scans'] = 'enabled' if 'enabled' in line.lower() else 'disabled'
                return status_info

            return {"error": "Unable to get XProtect status"}

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error(f"Error getting XProtect status: {e}")
            return {"error": str(e)}

    def _extract_hardware_model(self, hardware_output):
        """Extract hardware model identifier and name from system_profiler output"""
        try:
            # Extract both Model Identifier and Model Name
            model_identifier = None
            model_name = None

            for line in hardware_output.split('\n'):
                if 'Model Identifier:' in line:
                    model_identifier = line.split('Model Identifier:')[1].strip()
                elif 'Model Name:' in line:
                    model_name = line.split('Model Name:')[1].strip()

            # Return both as a tuple (identifier, name)
            return (model_identifier, model_name)
        except Exception:
            return (None, None)

    def _get_macos_marketing_name(self, version):
        """Get the marketing name for macOS version from system files"""
        try:
            # Try to get marketing name from Setup Assistant license file
            license_path = "/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf"
            awk_command = [
                "awk",
                "/SOFTWARE LICENSE AGREEMENT FOR macOS/",
                license_path
            ]

            result = subprocess.run(awk_command, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                # Extract marketing name using awk pipeline
                extract_command = [
                    "sh", "-c",
                    f"awk '/SOFTWARE LICENSE AGREEMENT FOR macOS/' '{license_path}' | awk -F 'macOS ' '{{print $NF}}' | awk '{{print substr($0, 0, length($0)-1)}}'"
                ]

                extract_result = subprocess.run(extract_command, capture_output=True, text=True)
                if extract_result.returncode == 0 and extract_result.stdout.strip():
                    marketing_name = extract_result.stdout.strip()
                    # Clean up the marketing name (remove version numbers if present)
                    marketing_name = marketing_name.split()[0]  # Take first word only
                    return f"macOS {marketing_name}"

        except Exception:
            pass

        # Fallback to hardcoded mapping if dynamic method fails
        try:
            major_version = int(version.split('.')[0]) if version else 0

            # Handle macOS 11+ versions (fallback mapping)
            if major_version >= 11:
                marketing_names = {
                    26: "macOS Tahoe",      # macOS 26.x (2025)
                    15: "macOS Sequoia",    # macOS 15.x (2024)
                    14: "macOS Sonoma",     # macOS 14.x (2023)
                    13: "macOS Ventura",    # macOS 13.x (2022)
                    12: "macOS Monterey",   # macOS 12.x (2021)
                    11: "macOS Big Sur"     # macOS 11.x (2020)
                }
                return marketing_names.get(major_version, self.MACOS_UNKNOWN)

            # Handle macOS 10.x versions
            elif major_version == 10:
                if version.startswith("10.15"):
                    return "macOS Catalina"
                elif version.startswith("10.14"):
                    return "macOS Mojave"
                elif version.startswith("10.13"):
                    return "macOS High Sierra"
                elif version.startswith("10.12"):
                    return "macOS Sierra"
                elif version.startswith("10.11"):
                    return "OS X El Capitan"
                elif version.startswith("10.10"):
                    return "OS X Yosemite"
                else:
                    return "macOS (Legacy)"

            return self.MACOS_UNKNOWN

        except (ValueError, IndexError):
            return self.MACOS_UNKNOWN
