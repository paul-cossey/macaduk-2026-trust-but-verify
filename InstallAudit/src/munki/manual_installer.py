# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Manual installer module for user-driven installations.
Performs security scans without Munki integration.
"""

import os
import time
import logging
import shutil
import tempfile
import subprocess
import plistlib
from datetime import datetime
from ..core.config_manager import get_config
from ..utils.dmg_mounter import mount_dmg, unmount_dmg
from .installation_validator import InstallationValidator

# Set up logging
logger = logging.getLogger(__name__)

# Constants
ARCHIVE_EXTENSIONS = ('.tar.gz', '.tar.bz2', '.tar.xz', '.zip')
STARTING_INSTALLATION_MSG = "\n   Starting installation...\n"


class ManualInstaller:
    """Handles manual user-driven installations with security scanning."""

    def __init__(self):
        """Initialize ManualInstaller."""
        # Initialize report_data if not already present
        if not hasattr(self, 'report_data') or self.report_data is None:
            self.report_data = {
                "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "system_info": {},
                "test_results": [],
                "security_events": [],
                "install_details": [],
                "uninstall_results": [],
                "loop_install_test": {},
                "loop_uninstall_test": {}
            }

    def prompt_for_installer_location(self) -> str:
        """
        Prompt user for installer file location.

        Returns:
            Path to the installer file
        """
        config = get_config()
        default_location = os.path.expanduser(config.get_default_save_location())

        print("\n=== Installer Location ===")
        print(f"Default location: {default_location}")
        print("Please provide the path to your installer file")
        print("Supported formats: .pkg, .dmg, .zip, .tar, .tar.gz, .tar.bz2, .tar.xz, .bz2, .xz, .gz, .app")

        while True:
            installer_path = input(f"Installer path [{default_location}]: ").strip()

            # Use default if user just presses Enter
            if not installer_path:
                installer_path = default_location
                print(f"   Using default: {installer_path}")

            # Normalize path:
            # 1. Remove surrounding quotes (single or double)
            if (installer_path.startswith('"') and installer_path.endswith('"')) or \
               (installer_path.startswith("'") and installer_path.endswith("'")):
                installer_path = installer_path[1:-1]

            # 2. Replace escaped spaces with actual spaces
            installer_path = installer_path.replace('\\ ', ' ')

            # 3. Expand user path (~/)
            installer_path = os.path.expanduser(installer_path)

            # 4. Normalize path (resolve ../, ./, etc.)
            installer_path = os.path.normpath(installer_path)

            # Check if it's a directory (user might have given Downloads folder)
            if os.path.isdir(installer_path):
                print(f"\n   📁 {installer_path} is a directory.")
                print("   Please drag and drop the installer file, or type the full path.")
                continue

            # Check if file exists
            if os.path.exists(installer_path):
                print(f"   ✅ Found installer: {os.path.basename(installer_path)}")
                return installer_path
            else:
                print(f"   ❌ File not found: {installer_path}")
                print("   Please verify the path and try again.")

    def _setup_manual_installation(self, installer_path):
        """Setup and initialize manual installation.

        Args:
            installer_path: Path to installer file

        Returns:
            tuple: (installer_name, clean_munki_name, start_time)
        """
        installer_name = os.path.basename(installer_path)
        self.installer_name = installer_name

        # Create cleaned munki name
        name_without_ext = os.path.splitext(installer_name)[0]
        self.clean_munki_name = name_without_ext.replace(' ', '_').replace('.', '_')

        print(f"\n\nStarting manual installation process for {installer_name}\n")
        start_time = datetime.now()

        # Add installer details to report
        self.report_data['install_details'].append("Installation Method: Manual (User-Driven)")
        self.report_data['install_details'].append(f"Installer File: {installer_name}")
        self.report_data['install_details'].append(f"Installer Path: {installer_path}")
        self.report_data['install_details'].append(
            f"Installation started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        # System snapshots and security setup
        self._run_system_checks()
        print("\nResetting security tool states")
        print("=" * 60)
        self._manage_security_tool_states(action="restore")
        print("   ✅ RansomWhere reset complete")

        self.knockknock_scanner = InstallationValidator.setup_knockknock_scanner(
            self.report_data
        )

        return installer_name, self.clean_munki_name, start_time

    def _analyze_installer_package(self, installer_path):
        """Analyze installer package for deprecated dependencies (PKG only)."""
        if not installer_path.lower().endswith('.pkg'):
            self._display_non_pkg_info(installer_path)
            return

        print("\nAnalyzing installer package for deprecated dependencies")
        print("=" * 60)
        try:
            from ..utils.package_analyzer import PackageAnalyzer
            package_analyzer = PackageAnalyzer()
            analysis_results = package_analyzer.analyze_single_package(installer_path)

            if analysis_results and "error" not in analysis_results:
                self.report_data["package_analysis"] = {
                    "packages_found": 1,
                    "packages_analyzed": 1,
                    "total_issues": len(analysis_results.get("deprecated_dependencies", [])),
                    "critical_issues": 1 if analysis_results.get("critical") else 0,
                    "analysis_results": [analysis_results]
                }

                if analysis_results.get("deprecated_dependencies"):
                    issues = len(analysis_results["deprecated_dependencies"])
                    print(f"   ⚠️  Found {issues} deprecated dependency issue(s)")
                    if analysis_results.get("critical"):
                        print("   🚨 Critical issue found (Python 2 usage)")
                else:
                    print("   ✅ No deprecated dependencies found")
            else:
                print("   ℹ️  Package analysis skipped or failed")

        except Exception as e:
            print(f"   ⚠️  Package analysis failed: {e}")
            logger.warning(f"Package analysis failed: {e}")

    def _display_non_pkg_info(self, installer_path):
        """Display info for non-PKG installer types."""
        file_ext = os.path.splitext(installer_path)[1].lower()
        full_name = os.path.basename(installer_path).lower()

        for archive_ext in ARCHIVE_EXTENSIONS:
            if full_name.endswith(archive_ext):
                file_ext = archive_ext
                break

        print(f"\nPackage analysis skipped (installer type: {file_ext or 'unknown'})")
        print("=" * 60)
        print("   ℹ️  Deprecated dependency analysis only available for .pkg files")
        print(f"   📦 File type: {file_ext or 'no extension'}")

        recognized_formats = ['.dmg', '.tar', '.bz2', '.xz', '.gz', '.app'] + list(ARCHIVE_EXTENSIONS)
        if file_ext in recognized_formats:
            print("   ✅ Recognized installer format")
        else:
            print("   ⚠️  Uncommon file type - please verify it's a valid installer")

    def _run_virustotal_analysis(self, installer_path):
        """Run VirusTotal malware analysis on the installer."""
        installer_name = os.path.basename(installer_path)
        print("\nAnalyzing installer for malware with VirusTotal")
        print("=" * 60)
        try:
            from ..security.virustotal_analyzer import VirusTotalAnalyzer

            vt_analyzer = VirusTotalAnalyzer(submit_new=True, timeout=300)
            print(f"   🔍 Analyzing {installer_name} for malware...")

            result = vt_analyzer.analyze_file(installer_path)

            # Store results
            self.report_data["virustotal_analysis"] = {
                "total_files": 1,
                "results": [result],
                "clean_files": 1 if result.get("status") == "clean" else 0,
                "malicious_files": 1 if result.get("status") == "malicious" else 0,
                "suspicious_files": 1 if result.get("status") == "suspicious" else 0,
                "error_files": 1 if result.get("status") == "error" else 0,
                "manual_check_required": 1 if result.get("requires_manual_check") else 0
            }

            # Display result
            self._display_virustotal_result(result, installer_name)

        except Exception as e:
            print(f"   ⚠️  VirusTotal analysis failed: {e}")
            logger.warning(f"VirusTotal analysis failed: {e}")

    def _display_virustotal_result(self, result, installer_name):
        """Display VirusTotal analysis result."""
        status = result.get("status", "unknown")
        if status == "clean":
            print(f"   ✅ {installer_name}: Clean (0 detections)")
        elif status == "malicious":
            detections = result.get("scan_results", {}).get("detection_ratio", "unknown")
            print(f"   🚨 {installer_name}: MALICIOUS ({detections} detections)")
        elif status == "suspicious":
            detections = result.get("scan_results", {}).get("detection_ratio", "unknown")
            print(f"   ⚠️  {installer_name}: Suspicious ({detections} detections)")
        elif status == "too_large":
            size_mb = result.get("file_size_mb", "unknown")
            print(f"   📏 {installer_name}: Too large ({size_mb} MB) - manual check required")
        elif status == "not_found":
            print(f"   ❓ {installer_name}: Not found in VirusTotal database")
        elif status == "error":
            print(f"   ❌ {installer_name}: Analysis failed - {result.get('message', 'unknown error')}")

    def _run_threatlabs_analysis(self, installer_path):
        """Run ThreatLabs binary analysis."""
        installer_name = os.path.basename(installer_path)
        print("\nAnalyzing installer with ThreatLabs")
        print("=" * 60)
        try:
            from ..core.config_manager import get_config
            config = get_config()

            if not config.is_threatlabs_enabled():
                print("   ℹ️  ThreatLabs scanning disabled in config - skipping binary analysis")
                return

            from ..security.threatlabs_scanner import ThreatLabsScanner
            from ..utils.binary_extractor import BinaryExtractor

            threatlabs = ThreatLabsScanner()
            if not threatlabs.is_available():
                print("   ℹ️  ThreatLabs API key not configured - skipping binary analysis")
                return

            print(f"   📦 Extracting binaries from {installer_name}...")
            extractor = BinaryExtractor()
            binaries = extractor.extract_binaries(installer_path)

            if not binaries:
                print("   ℹ️  No binaries extracted for analysis")
                return

            print(f"      Found {len(binaries)} Mach-O binary(ies)")

            # Submit Mach-O executables to ThreatLabs for analysis
            # Use otool filetype to identify true executables vs libraries/bundles
            # Only EXECUTE filetype binaries are submitted (excludes DYLIB, BUNDLE, etc.)
            # This prevents wasting API calls on files ThreatLabs can't analyze (returns HTTP 415)
            scannable_binaries = [
                b for b in binaries
                if 'mach-o' in b.get('type', '').lower()
                and b.get('filetype') == 'EXECUTE'
            ]
            excluded_count = len([b for b in binaries if b.get('filetype') != 'EXECUTE'])

            if not scannable_binaries:
                print("   ℹ️  No executable binaries found (libraries/bundles/plugins excluded)")
                scan_results = {'total_binaries': 0, 'submitted': 0, 'results': []}
            else:
                print(f"   🔍 Submitting {len(scannable_binaries)} binary(ies) to ThreatLabs...")
                if excluded_count > 0:
                    logger.info(f"Note: {excluded_count} non-executable(s) excluded (libraries/bundles/plugins not supported by ThreatLabs)")
                scan_results = threatlabs.scan_binaries(scannable_binaries, max_submissions=10)

            summary = threatlabs.get_summary(scan_results)
            self.report_data["threatlabs_analysis"] = {"summary": summary, "results": scan_results}

            # Display summary
            self._display_threatlabs_summary(summary)
            extractor.cleanup()

        except Exception as e:
            print(f"   ⚠️  ThreatLabs analysis failed: {e}")
            logger.warning(f"ThreatLabs analysis failed: {e}")

    def _display_threatlabs_summary(self, summary):
        """Display ThreatLabs analysis summary."""
        if summary['malicious'] > 0:
            print(f"   🚨 THREATS DETECTED: {summary['malicious']} malicious binary(ies)!")
        elif summary['suspicious'] > 0:
            print(f"   ⚠️  {summary['suspicious']} suspicious binary(ies) detected")
        elif summary['too_large'] > 0 and summary['clean'] == 0 and summary.get('unsupported', 0) == 0:
            print(f"   ⚠️  {summary['too_large']} binary(ies) too large - could not scan")
        else:
            # Show comprehensive summary
            if summary['clean'] > 0:
                print(f"   ✅ {summary['clean']} binary(ies) analyzed - all clean")
            if summary['too_large'] > 0:
                print(f"   ⚠️  {summary['too_large']} binary(ies) skipped (too large)")
            if summary.get('unsupported', 0) > 0:
                print(f"   ℹ️  {summary['unsupported']} binary(ies) skipped (file type not supported by ThreatLabs API)")
            if summary['clean'] == 0 and summary['too_large'] == 0 and summary.get('unsupported', 0) == 0:
                print("   ℹ️  No binaries successfully analyzed")

    def _install_pkg_file(self, pkg_path: str) -> bool:
        """Install a PKG file using the system installer.

        Args:
            pkg_path: Path to the PKG file

        Returns:
            True if installation succeeded, False otherwise
        """
        print(f"   📦 Installing PKG: {os.path.basename(pkg_path)}")
        print("   ⏳ Installation in progress, please wait...")

        start_time = time.time()
        try:
            result = subprocess.run(
                ['sudo', '/usr/sbin/installer', '-pkg', pkg_path, '-target', '/'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            elapsed = time.time() - start_time

            if result.returncode == 0:
                print(f"   ✅ PKG installed successfully (took {elapsed:.1f}s)")
                return True
            else:
                print(f"   ❌ PKG installation failed: {result.stderr}")
                logger.error(f"PKG installation failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print("   ❌ PKG installation timed out")
            logger.error("PKG installation timed out after 5 minutes")
            return False
        except Exception as e:
            print(f"   ❌ Error installing PKG: {e}")
            logger.error(f"Error installing PKG: {e}")
            return False

    def _copy_app_to_applications(self, app_path: str, app_name: str = None) -> bool:
        """Copy an app bundle to /Applications.

        Args:
            app_path: Path to the .app bundle
            app_name: Optional custom name for the destination

        Returns:
            True if copy succeeded, False otherwise
        """
        if not app_name:
            app_name = os.path.basename(app_path)

        dest_path = os.path.join('/Applications', app_name)

        print(f"   📂 Copying {app_name} to /Applications")
        start_time = time.time()
        try:
            # Remove existing app if present
            if os.path.exists(dest_path):
                print(f"   🗑️  Removing existing {app_name}...")
                subprocess.run(['sudo', 'rm', '-rf', dest_path], check=True)

            # Copy app bundle
            print("   ⏳ Copying files, please wait...")
            subprocess.run(['sudo', 'cp', '-R', app_path, dest_path], check=True, timeout=300)

            elapsed = time.time() - start_time
            print(f"   ✅ {app_name} copied successfully (took {elapsed:.1f}s)")
            return True

        except subprocess.TimeoutExpired:
            print("   ❌ Copy operation timed out")
            logger.error(f"Copy operation timed out for {app_name}")
            return False
        except Exception as e:
            print(f"   ❌ Error copying app: {e}")
            logger.error(f"Error copying {app_name} to /Applications: {e}")
            return False

    def _install_dmg_file(self, dmg_path: str) -> bool:
        """Mount DMG and install contents (PKG or app bundle).

        Args:
            dmg_path: Path to the DMG file

        Returns:
            True if installation succeeded, False otherwise
        """
        print(f"   💿 Step 1/3: Mounting DMG: {os.path.basename(dmg_path)}...")
        mount_point = None
        start_time = time.time()

        try:
            mount_point = mount_dmg(dmg_path)

            if not mount_point:
                print(f"   ❌ Failed to mount DMG: {os.path.basename(dmg_path)}")
                return False

            mount_elapsed = time.time() - start_time
            print(f"   ✅ DMG mounted successfully (took {mount_elapsed:.1f}s)")

            # Scan mount point for installable content
            print("   📋 Step 2/3: Scanning DMG contents...")
            installed = False
            items = os.listdir(mount_point)

            # Look for PKG files first
            pkg_files = [f for f in items if f.lower().endswith('.pkg')]
            if pkg_files:
                print(f"   🔍 Found PKG installer: {pkg_files[0]}")
                for pkg_file in pkg_files:
                    pkg_path = os.path.join(mount_point, pkg_file)
                    if self._install_pkg_file(pkg_path):
                        installed = True
                        break

            # Look for app bundles if no PKG found
            if not installed:
                app_bundles = [f for f in items if f.lower().endswith('.app')]
                if app_bundles:
                    print(f"   🔍 Found application: {app_bundles[0]}")
                    for app_bundle in app_bundles:
                        app_path = os.path.join(mount_point, app_bundle)
                        if os.path.isdir(app_path):
                            if self._copy_app_to_applications(app_path):
                                installed = True
                                break

            # Look for folders to copy if no app bundles
            if not installed:
                folders = [
                    f for f in items if os.path.isdir(os.path.join(mount_point, f))
                    and not f.startswith('.')
                    and f not in ['.background', '.Trashes', '.fseventsd']
                ]
                if folders:
                    for folder in folders:
                        folder_path = os.path.join(mount_point, folder)
                        if self._copy_app_to_applications(folder_path, folder):
                            installed = True
                            break

            if not installed:
                print("   ⚠️  No installable content found in DMG")
                print(f"   📁 Contents: {', '.join(items)}")

            total_elapsed = time.time() - start_time
            if installed:
                print(f"\n   🎉 DMG installation completed successfully (total time: {total_elapsed:.1f}s)")

            return installed

        except subprocess.TimeoutExpired:
            print("   ❌ DMG mount operation timed out")
            return False
        except Exception as e:
            print(f"   ❌ Error processing DMG: {e}")
            logger.error(f"Error processing DMG {dmg_path}: {e}")
            return False
        finally:
            # Unmount DMG
            if mount_point:
                print("   🔄 Step 3/3: Unmounting DMG...")
                if unmount_dmg(mount_point):
                    print("   ✅ DMG unmounted successfully")
                else:
                    print("   ⚠️  DMG unmount may not have completed cleanly")

    def _install_archive_file(self, archive_path: str) -> bool:
        """Unpack archive and copy app bundle or folder to /Applications.

        Args:
            archive_path: Path to the archive file

        Returns:
            True if installation succeeded, False otherwise
        """
        print(f"   📦 Step 1/3: Unpacking archive: {os.path.basename(archive_path)}...")
        temp_dir = None
        start_time = time.time()

        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix='manual_install_')

            # Determine archive type and unpack
            file_name = os.path.basename(archive_path).lower()

            if file_name.endswith('.zip'):
                result = subprocess.run(
                    ['unzip', '-q', archive_path, '-d', temp_dir],
                    capture_output=True,
                    timeout=120
                )
            elif file_name.endswith(('.tar.gz', '.tgz')):
                result = subprocess.run(
                    ['tar', '-xzf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    timeout=120
                )
            elif file_name.endswith(('.tar.bz2', '.tbz')):
                result = subprocess.run(
                    ['tar', '-xjf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    timeout=120
                )
            elif file_name.endswith(('.tar.xz', '.txz')):
                result = subprocess.run(
                    ['tar', '-xJf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    timeout=120
                )
            elif file_name.endswith('.tar'):
                result = subprocess.run(
                    ['tar', '-xf', archive_path, '-C', temp_dir],
                    capture_output=True,
                    timeout=120
                )
            elif file_name.endswith('.gz'):
                result = subprocess.run(
                    ['gunzip', '-c', archive_path],
                    capture_output=True,
                    timeout=120
                )
                # For .gz, output goes to stdout
                if result.returncode == 0:
                    output_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(archive_path))[0])
                    with open(output_file, 'wb') as f:
                        f.write(result.stdout)
            elif file_name.endswith('.bz2'):
                result = subprocess.run(
                    ['bunzip2', '-c', archive_path],
                    capture_output=True,
                    timeout=120
                )
                # For .bz2, output goes to stdout
                if result.returncode == 0:
                    output_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(archive_path))[0])
                    with open(output_file, 'wb') as f:
                        f.write(result.stdout)
            elif file_name.endswith('.xz'):
                result = subprocess.run(
                    ['xz', '-d', '-c', archive_path],
                    capture_output=True,
                    timeout=120
                )
                # For .xz, output goes to stdout
                if result.returncode == 0:
                    output_file = os.path.join(temp_dir, os.path.splitext(os.path.basename(archive_path))[0])
                    with open(output_file, 'wb') as f:
                        f.write(result.stdout)
            else:
                print("   ❌ Unsupported archive format")
                return False

            if result.returncode != 0:
                print(f"   ❌ Failed to unpack archive: {result.stderr if result.stderr else 'Unknown error'}")
                return False

            unpack_elapsed = time.time() - start_time
            print(f"   ✅ Archive unpacked successfully (took {unpack_elapsed:.1f}s)")

            # Look for app bundles or folders to install
            print("   🔍 Step 2/3: Searching for installable content...")
            installed = False
            for root, dirs, _files in os.walk(temp_dir):
                # Look for .app bundles
                for dir_name in dirs:
                    if dir_name.lower().endswith('.app'):
                        app_path = os.path.join(root, dir_name)
                        if self._copy_app_to_applications(app_path):
                            installed = True
                            break
                if installed:
                    break

            # If no app bundle found, look for a single top-level folder to copy
            if not installed:
                top_level_items = os.listdir(temp_dir)
                folders = [
                    f for f in top_level_items
                    if os.path.isdir(os.path.join(temp_dir, f))
                    and not f.startswith('.')
                    and not f.startswith('__MACOSX')
                ]

                if len(folders) == 1:
                    folder_path = os.path.join(temp_dir, folders[0])
                    if self._copy_app_to_applications(folder_path, folders[0]):
                        installed = True

            if not installed:
                print("   ⚠️  No installable content found in archive")

            total_elapsed = time.time() - start_time
            if installed:
                print(f"\n   🎉 Archive installation completed successfully (total time: {total_elapsed:.1f}s)")

            return installed

        except subprocess.TimeoutExpired:
            print("   ❌ Archive unpacking timed out")
            return False
        except Exception as e:
            print(f"   ❌ Error processing archive: {e}")
            logger.error(f"Error processing archive {archive_path}: {e}")
            return False
        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                print("   🧹 Step 3/3: Cleaning up temporary files...")
                try:
                    shutil.rmtree(temp_dir)
                    print("   ✅ Cleanup completed")
                except Exception as e:
                    logger.warning(f"Failed to clean up temp directory: {e}")

    def _auto_install_media(self, installer_path: str) -> bool:
        """Automatically install media based on file type.

        Args:
            installer_path: Path to installer media

        Returns:
            True if installation succeeded, False otherwise
        """
        file_name = os.path.basename(installer_path).lower()

        print("\n🤖 Auto-Installation Mode")
        print("=" * 60)
        print(f"   📂 File: {os.path.basename(installer_path)}")

        # Determine file type and display info
        if file_name.endswith('.pkg'):
            print("   📦 Type: PKG Installer")
            print(STARTING_INSTALLATION_MSG)
            return self._install_pkg_file(installer_path)
        elif file_name.endswith('.dmg'):
            print("   💿 Type: Disk Image (DMG)")
            print(STARTING_INSTALLATION_MSG)
            return self._install_dmg_file(installer_path)
        elif file_name.endswith('.app'):
            print("   🎯 Type: Application Bundle")
            print(STARTING_INSTALLATION_MSG)
            return self._copy_app_to_applications(installer_path)
        elif file_name.endswith(('.tar', '.bz2', '.xz', '.gz') + ARCHIVE_EXTENSIONS):
            print("   📦 Type: Archive")
            print(STARTING_INSTALLATION_MSG)
            return self._install_archive_file(installer_path)
        else:
            print("   ❌ Unsupported file type for auto-installation")
            return False

    def _start_monitoring_and_guide_user(self, installer_path, start_time):
        """Start security monitoring and provide user installation guidance."""
        print("\nStarting Security Monitoring")
        print("=" * 60)
        print("   🔍 Launching security monitoring tools...")
        print("   📝 Events will be captured during installation")

        self.security_start_time = start_time.strftime("%Y-%m-%d %H:%M:%S")
        success = self.start_security_monitoring()

        self.report_data['security_monitoring_active'] = success
        print("   ✅ Security monitoring active" if success else "   ⚠️  Some security monitoring tools may not have started")

        time.sleep(2)

        # Check if auto-install is enabled
        config = get_config()
        auto_install_enabled = config.is_auto_install_enabled()
        auto_install_succeeded = False

        if auto_install_enabled:
            # Perform automatic installation
            print("\n🤖 Automatic Installation Enabled")
            print("=" * 60)
            print(f"📦 Installer: {installer_path}")

            auto_install_succeeded = self._auto_install_media(installer_path)
            if auto_install_succeeded:
                print("\n✅ Automatic installation completed")
                print("\n   📱 Next Steps:")
                print("   1. Launch the installed application")
                print("   2. Test key functionality (grant permissions if prompted)")
                print("   3. Quit the application when testing is complete")
            else:
                print("\n⚠️  Automatic installation failed - please install manually")
                self._display_manual_install_guidance(installer_path)
        else:
            # Manual installation mode - display guidance
            self._display_manual_install_guidance(installer_path)

        print("\n   ⚠️  Security monitoring is active - installation events will be captured")
        print("=" * 60)

        # Different prompt based on whether auto-install was used
        if auto_install_succeeded:
            input("\nPress Enter when you've finished testing the application...")
        else:
            input("\nPress Enter when installation is COMPLETE and you've launched the app...")

        end_time = datetime.now()
        self.report_data['install_details'].append(
            f"Installation completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.report_data['install_details'].append(
            f"Installation duration: {InstallationValidator.format_installation_duration(start_time, end_time)}"
        )
        print("\n✅ Installation reported as complete by user")

    def _display_manual_install_guidance(self, installer_path):
        """Display manual installation guidance based on file type.

        Args:
            installer_path: Path to installer file
        """
        print("\nUser Installation Phase")
        print("=" * 60)
        print(f"📦 Installer: {installer_path}")

        # File-type specific guidance
        file_name = os.path.basename(installer_path).lower()
        if file_name.endswith('.pkg'):
            print("   ℹ️  PKG Installer - Double-click to run the installer")
        elif file_name.endswith('.dmg'):
            print("   ℹ️  DMG Image - Mount the image and run any installer inside")
        elif file_name.endswith('.app'):
            print("   ℹ️  Application Bundle - Drag to /Applications or double-click to run")
        elif file_name.endswith(('.tar', '.bz2', '.xz', '.gz') + ARCHIVE_EXTENSIONS):
            print("   ℹ️  Archive - Extract the archive, then run the installer inside")
        else:
            print("   ℹ️  Please install the application using the appropriate method")

        print("\n   Please perform the following steps:")
        print("   1. Install the application")
        print("   2. Launch the application at least once")
        print("   3. Test any key functionality if needed")
        print("   4. Quit the application when finished")

    def _wait_for_security_events(self):
        """Check for any remaining security events."""
        print("\nMonitoring for security and system events")
        print("=" * 60)
        print("   Collecting security events...")

        try:
            # Give a brief moment for any final events to be captured
            time.sleep(2)

            # Final check for monitoring events
            self.check_monitoring_events()

        except Exception as e:
            logger.error(f"Error during monitoring: {e}")

        self.stop_security_monitoring()

    def _run_post_install_tasks(self, installer_name):
        """Run post-installation tasks."""
        # KnockKnock scan
        if self.report_data.get('knockknock_available') and hasattr(self, 'knockknock_scanner'):
            print("\nRunning KnockKnock Post-Installation Analysis")
            print("=" * 60)
            if self.knockknock_scanner.run_post_install_scan():
                comparison = self.knockknock_scanner.compare_scans()
                self.report_data['knockknock_results'] = {
                    'summary': self.knockknock_scanner.get_scan_summary(),
                    'comparison': comparison
                }
                print("\n📊 KnockKnock Analysis Results:")
                print(f"   • New persistence items: {comparison['new_count']}")
                print(f"   • Modified items: {comparison['modified_count']}")
                print(f"   • Removed items: {comparison['removed_count']}")
            else:
                print("   ⚠️  KnockKnock post-installation scan failed")
                self.report_data['knockknock_results'] = {'error': 'Post-installation scan failed'}

        # Security scans
        self.run_security_scans()

        # Configuration profile generation
        print("\nCode Signing Verification & Configuration Profile Generation")
        print("=" * 60)
        try:
            if not hasattr(self, 'report_data') or self.report_data is None:
                self.report_data = {}

            # Initialize empty configuration profiles structure
            if 'configuration_profiles' not in self.report_data:
                self.report_data['configuration_profiles'] = {
                    'generated_profiles': [],
                    'profile_statistics': {'total_profiles': 0, 'total_applications': 0},
                    'saved_files': []
                }

            output_dir = getattr(self, 'output_directory', None)
            clean_name = getattr(self, 'clean_munki_name', installer_name)

            # Allow user to manually drag/drop apps for analysis
            self._check_code_signing(munki_item_name=clean_name, output_directory=output_dir)

            # Always enhance profiles with system-detected BTM changes (regardless of manual app analysis)
            self._enhance_profiles_with_system_data()

            # Check if we generated any profiles (from manual analysis or BTM detection)
            profiles_generated = (
                self.report_data.get('configuration_profiles', {}).get('generated_profiles', [])
            )

            if profiles_generated:
                print("\n✅ Configuration profile generation completed")
            else:
                # No profiles from either manual or BTM detection
                self._set_empty_configuration_profiles()

        except Exception as e:
            import traceback
            logger.error(f"Error in code signing verification: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"❌ Error in code signing verification: {e}")
            self._set_empty_configuration_profiles(error=str(e))

        # Completion message is now displayed in main workflow after all prompts
        # self._display_completion_message()

    def _set_empty_configuration_profiles(self, error=None):
        """Set empty configuration profiles in report data."""
        base_data = {
            'generated_profiles': [],
            'profile_statistics': {'total_profiles': 0, 'total_applications': 0},
            'saved_files': []
        }
        if error:
            base_data['error'] = error
            base_data['profile_summary'] = f"## Configuration Profiles\n\nError during profile generation: {error}\n"
        else:
            base_data['profile_summary'] = "## Configuration Profiles\n\nNo applications were analyzed for configuration profiles.\n"

        self.report_data['configuration_profiles'] = base_data

    def _enhance_profiles_with_system_data(self):
        """
        Enhance generated profiles with system-detected data (BTM changes, login items).
        Uses only the NEW/CHANGED items detected during installation, not all system items.
        """
        try:
            print("\n🔍 Enhancing profiles with system-detected login items...")

            # Debug: Check if report_data exists
            if not hasattr(self, 'report_data') or self.report_data is None:
                print("   ⚠️  DEBUG: No report_data found!")
                logger.error("No report_data in _enhance_profiles_with_system_data")
                return

            # Get BTM changes that were detected (not all BTM items)
            system_changes = self.report_data.get('system_changes', {})
            login_item_changes = system_changes.get('login_items', [])

            # Debug: Show what we found
            print(f"   🐛 DEBUG: system_changes keys: {list(system_changes.keys())}")
            print(f"   🐛 DEBUG: login_item_changes count: {len(login_item_changes) if login_item_changes else 0}")

            # Debug: Show types in the list
            if login_item_changes:
                type_counts = {}
                for item in login_item_changes:
                    item_type = type(item).__name__
                    type_counts[item_type] = type_counts.get(item_type, 0) + 1
                print(f"   🐛 DEBUG: login_item_changes types: {type_counts}")

            if not login_item_changes:
                logger.info("No login item changes detected - skipping profile enhancement")
                print("   ℹ️  No new login items detected during installation")
                return

            print(f"   📋 Found {len(login_item_changes)} new login item(s) to process")

            # Extract unique apps from the detected changes, grouped by team_id
            apps_to_enhance = self._extract_apps_from_login_item_changes(login_item_changes)

            if not apps_to_enhance:
                logger.info("No valid apps extracted from login item changes")
                print("   ℹ️  No valid apps could be extracted from login item changes")
                return

            # Enhance profiles for each detected app/team
            enhanced_count = self._enhance_profiles_for_detected_items(apps_to_enhance)

            # Display results
            self._display_enhancement_results(enhanced_count)

        except Exception as e:
            import traceback
            logger.error(f"Error enhancing profiles with system data: {e}", exc_info=True)
            print(f"   ⚠️  Error enhancing profiles: {e}")
            print(f"   🐛 DEBUG Traceback: {traceback.format_exc()}")

    def _extract_apps_from_login_item_changes(self, login_item_changes):
        """
        Extract unique apps from detected login item changes, grouped by team_id.

        Args:
            login_item_changes: List of login item changes (dicts and strings) from system comparison

        Returns:
            Dict mapping team_id to list of (app_name, bundle_id, team_id) tuples
        """
        team_groups = {}

        for item_change in login_item_changes:
            # Process string items (file changes like "New file: LaunchAgent: ...")
            if isinstance(item_change, str):
                item_info = self._parse_launch_file_string(item_change)
                if item_info:
                    app_name, bundle_id, team_id, rule_type = item_info
                    if team_id not in team_groups:
                        team_groups[team_id] = []
                    # Store with rule_type for profile generation
                    team_groups[team_id].append((app_name, bundle_id, team_id, rule_type))
                    logger.info(f"Added login item from launch file: {app_name} ({bundle_id}, team: {team_id}, rule: {rule_type})")
                else:
                    logger.debug(f"Could not parse launch file string: {item_change}")
                continue

            # Process dictionary items (BTM changes)
            if not isinstance(item_change, dict):
                logger.warning(f"Unexpected item type: {type(item_change)}")
                continue

            item_info = self._parse_login_item_change(item_change)
            if not item_info:
                continue

            app_name, bundle_id, team_id, rule_type = item_info

            # Group by team_id
            if team_id not in team_groups:
                team_groups[team_id] = []

            # Use the rule_type determined by URL analysis
            team_groups[team_id].append((app_name, bundle_id, team_id, rule_type))
            logger.info(f"Added login item for enhancement: {app_name} ({bundle_id}, team: {team_id}, rule: {rule_type})")

        return team_groups

    def _parse_login_item_change(self, item_change):
        """Parse a login item change dictionary and extract app info."""
        identifier = item_change.get('identifier', '')
        team_id = item_change.get('team_identifier', '')
        name = item_change.get('name', '')
        url = item_change.get('url', '')

        # Parse bundle ID from identifier (remove legacy agent prefix like "8.")
        bundle_id = self._extract_bundle_id_from_identifier(identifier)

        # Validate required data
        if not bundle_id or not team_id:
            logger.debug(f"Skipping item without bundle_id or team_id: {identifier}")
            return None

        # Skip Apple items
        if bundle_id.startswith('com.apple.'):
            logger.debug(f"Skipping Apple item: {bundle_id}")
            return None

        # Determine app name
        app_name = self._derive_app_name(name, bundle_id)

        # Determine rule type based on URL
        # If URL contains LaunchAgents or LaunchDaemons, use Label rule type
        rule_type = 'BundleIdentifier'  # Default for regular apps
        if url and ('/LaunchAgents/' in url or '/LaunchDaemons/' in url):
            rule_type = 'Label'
            logger.info(f"Detected LaunchAgent/Daemon from URL: {url}, using rule_type=Label")

        return app_name, bundle_id, team_id, rule_type

    def _extract_bundle_id_from_identifier(self, identifier):
        """Extract bundle ID from BTM identifier."""
        if not identifier or '.' not in identifier:
            return identifier

        parts = identifier.split('.', 1)
        if parts[0].isdigit() and len(parts) > 1:
            return parts[1]
        return identifier

    def _derive_app_name(self, name, bundle_id):
        """Derive app name from name or bundle_id."""
        if name and name not in ['(null)', 'Unknown']:
            return name

        # Derive from bundle_id (last component)
        simple_name = bundle_id.split('.')[-1]

        # If the name has underscores, capitalize each part
        if '_' in simple_name:
            return ''.join(word.capitalize() for word in simple_name.split('_'))

        # For camelCase names, just capitalize the first letter and preserve the rest
        return simple_name[0].upper() + simple_name[1:] if simple_name else simple_name

    def _parse_launch_file_string(self, file_string):
        """
        Parse LaunchAgent/LaunchDaemon file string and extract app info from plist.

        Args:
            file_string: String like "New file: LaunchAgent: com.example.app.plist"

        Returns:
            Tuple of (app_name, bundle_id, team_id) or None if parsing fails
        """
        try:
            # Parse the string format: "New file: LaunchAgent: filename.plist"
            if ':' not in file_string:
                return None

            parts = file_string.split(': ')
            if len(parts) < 3:
                return None

            item_type = parts[1].strip()  # "LaunchAgent" or "LaunchDaemon"
            plist_filename = parts[2].strip()

            # Construct full path
            if item_type == 'LaunchAgent':
                plist_path = f"/Library/LaunchAgents/{plist_filename}"
            elif item_type == 'LaunchDaemon':
                plist_path = f"/Library/LaunchDaemons/{plist_filename}"
            else:
                logger.debug(f"Unknown launch item type: {item_type}")
                return None

            # Check if file exists
            if not os.path.exists(plist_path):
                logger.debug(f"Plist file not found: {plist_path}")
                return None

            # Read plist to get bundle ID and program path
            with open(plist_path, 'rb') as f:
                plist_data = plistlib.load(f)

            # Get bundle ID from Label (this is the key identifier for Launch items)
            bundle_id = plist_data.get('Label', '')
            if not bundle_id:
                logger.debug(f"No Label found in plist: {plist_path}")
                return None

            logger.info(f"Extracted Label from {plist_filename}: {bundle_id}")

            # Skip Apple items
            if bundle_id.startswith('com.apple.'):
                logger.debug(f"Skipping Apple item: {bundle_id}")
                return None

            # Get program path for codesign analysis
            program_path = None
            if 'Program' in plist_data:
                program_path = plist_data['Program']
            elif 'ProgramArguments' in plist_data and plist_data['ProgramArguments']:
                program_path = plist_data['ProgramArguments'][0]

            # Extract team ID using codesign
            team_id = self._extract_team_id_from_program(program_path) if program_path else None

            if not team_id:
                logger.debug(f"Could not extract team ID for {bundle_id}")
                return None

            # Derive app name from bundle ID
            app_name = self._derive_app_name('', bundle_id)

            logger.info(f"Parsed launch file: {app_name} ({bundle_id}, team: {team_id}) - will use Label rule type")
            # Return tuple with rule_type indicator: (app_name, bundle_id, team_id, rule_type)
            return app_name, bundle_id, team_id, 'Label'

        except Exception as e:
            logger.error(f"Error parsing launch file string '{file_string}': {e}")
            return None

    def _extract_team_id_from_program(self, program_path):
        """
        Extract team ID from program binary using codesign.

        Args:
            program_path: Path to the program binary

        Returns:
            Team ID string or None if extraction fails
        """
        try:
            if not program_path or not os.path.exists(program_path):
                return None

            # Run codesign to get team ID
            result = subprocess.run(
                ['/usr/bin/codesign', '-dv', '--verbose=4', program_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse stderr for TeamIdentifier
            for line in result.stderr.split('\n'):
                if 'TeamIdentifier=' in line:
                    team_id = line.split('TeamIdentifier=')[1].strip()
                    return team_id

            return None

        except Exception as e:
            logger.error(f"Error extracting team ID from {program_path}: {e}")
            return None

    def _enhance_profiles_for_detected_items(self, apps_to_enhance):
        """
        Enhance profiles for detected login items grouped by team.

        Args:
            apps_to_enhance: Dict mapping team_id to list of (app_name, bundle_id, team_id)

        Returns:
            int: Number of profiles enhanced
        """
        enhanced_count = 0

        # Process each team group
        for team_id, apps_list in apps_to_enhance.items():
            # Use the first app as the representative name (apps_list items now have 4 elements including rule_type)
            app_name = apps_list[0][0]

            # Log what we're processing
            app_names = ', '.join([item[0] for item in apps_list])
            print(f"   🔧 Generating profile for {len(apps_list)} item(s): {app_names}")
            logger.info(f"Generating profile for team {team_id} with {len(apps_list)} items")

            # Create login items list with rule_type info for profile generation
            login_items_for_profile = []
            for _app_name_item, bundle_id_item, team_id_item, rule_type in apps_list:
                login_items_for_profile.append({
                    'bundle_id': bundle_id_item,
                    'team_id': team_id_item,
                    'rule_type': rule_type,
                    'detection_reason': f"Detected via {'LaunchAgent/Daemon' if rule_type == 'Label' else 'BTM'}"
                })
                logger.info(f"DEBUG: Adding login item: bundle_id={bundle_id_item}, team_id={team_id_item}, rule_type={rule_type}")

            # Generate profile directly with the collected items
            updated_profiles = self._generate_profile_for_login_items(
                app_name, login_items_for_profile
            )

            if updated_profiles:
                enhanced_count += len(updated_profiles)
                print(f"      ✅ Generated {len(updated_profiles)} profile(s)")

                # Update report data with enhanced profiles
                self._update_report_with_enhanced_profiles(app_name, updated_profiles)

        return enhanced_count

    def _generate_profile_for_login_items(self, app_name, login_items_data):
        """
        Generate Managed Login Items profile directly from collected login items.

        Args:
            app_name: Application name for the profile
            login_items_data: List of dicts with bundle_id, team_id, and rule_type

        Returns:
            List of profile dictionaries
        """
        try:
            from ..profiles.profile_templates import ProfileTemplates
            templates = ProfileTemplates()

            # Generate the profile using our template with rule_type support
            profile = templates.create_managed_login_items_profile(app_name, login_items_data)
            filename = f"Managed Login Items - Allow {app_name}.mobileconfig"

            profile_dict = {
                'type': 'Managed Login Items',
                'filename': filename,
                'profile': profile,
                'app_name': app_name,
                'enhanced': True,
                'items_count': len(login_items_data),
                'data_source': 'system_detected'
            }

            logger.info(f"Generated Managed Login Items profile for {app_name} with {len(login_items_data)} items")
            return [profile_dict]

        except Exception as e:
            logger.error(f"Error generating profile for {app_name}: {e}")
            return []

    def _create_filtered_btm_data(self, login_item_changes, target_team_id):
        """
        Create filtered BTM data containing only items from detected changes for a specific team.

        Args:
            login_item_changes: List of detected login item changes
            target_team_id: Team ID to filter for

        Returns:
            str: Filtered BTM data in the format expected by the analyzer
        """
        filtered_items = []

        for item_change in login_item_changes:
            team_id = item_change.get('team_identifier', '')
            if team_id == target_team_id and 'raw_btm_section' in item_change:
                # Include the raw BTM section for this item
                filtered_items.append(item_change['raw_btm_section'])

        # Join all sections with newlines
        filtered_btm = '\n'.join(filtered_items)
        logger.info(f"Created filtered BTM data for team {target_team_id}: {len(filtered_btm)} bytes, {len(filtered_items)} items")

        return filtered_btm

    def _update_report_with_enhanced_profiles(self, app_name, updated_profiles):
        """Update report data with enhanced profiles."""
        if 'configuration_profiles' not in self.report_data:
            return

        existing_profiles = self.report_data['configuration_profiles'].get('generated_profiles', [])

        # Replace existing profiles for this app with enhanced versions
        filtered_profiles = [p for p in existing_profiles if p.get('app_name') != app_name]
        filtered_profiles.extend(updated_profiles)

        self.report_data['configuration_profiles']['generated_profiles'] = filtered_profiles

        # Ensure munki_item_name is set for EA/recipe generation
        if not self.munki_item_name and hasattr(self, 'clean_munki_name'):
            self.munki_item_name = self.clean_munki_name

        # Re-save profiles
        saved_files = self.save_profiles(updated_profiles)
        if saved_files:
            # Update saved files list
            existing_files = self.report_data['configuration_profiles'].get('saved_files', [])
            for filename in saved_files:
                if filename not in existing_files:
                    existing_files.append(filename)
            self.report_data['configuration_profiles']['saved_files'] = existing_files

    def _display_enhancement_results(self, enhanced_count):
        """Display profile enhancement results."""
        if enhanced_count > 0:
            print(f"\n✅ Profile enhancement completed - enhanced {enhanced_count} profile(s)")
        else:
            print("\n   ℹ️  No profiles needed enhancement")

    def _display_completion_message(self):
        """Display completion message."""
        print("\n\n✅ Manual installation testing completed successfully")
        print("\n" + "=" * 60)
        print("UNINSTALLATION:")
        print("⚠️  Please manually uninstall the application when testing is complete.")
        print("   No automated uninstallation is performed for manual installs.")
        print("=" * 60)

    def manual_install_and_test(self, installer_path: str = None):
        """
        Manual installation workflow with security scanning.

        Args:
            installer_path: Optional path to installer file

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get installer location if not provided
            if not installer_path:
                installer_path = self.prompt_for_installer_location()

            # Setup and initialize
            installer_name, _, start_time = self._setup_manual_installation(installer_path)

            # Analyze installer package
            self._analyze_installer_package(installer_path)

            # Run security analyses
            self._run_virustotal_analysis(installer_path)
            self._run_threatlabs_analysis(installer_path)

            # Start monitoring and guide user through installation
            self._start_monitoring_and_guide_user(installer_path, start_time)

            # Wait for security events
            self._wait_for_security_events()

            # Compare system states BEFORE profile generation so BTM changes are available
            print("\nComparing system states")
            print("=" * 60)
            system_changes = self._compare_system_checks()
            if system_changes is None:
                print("⚠️  Warning: Unable to compare system states")

            # Run post-installation tasks (includes profile generation with BTM changes)
            self._run_post_install_tasks(installer_name)

            return True

        except KeyboardInterrupt:
            print("\n\n❌ Installation cancelled by user")
            return False
        except Exception as e:
            logger.error(f"Error during manual installation: {e}", exc_info=True)
            print(f"\n❌ Error during manual installation: {e}")
            return False
