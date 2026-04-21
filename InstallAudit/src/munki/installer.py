# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Munki installer module for managing software installation and uninstallation.
"""

import subprocess
from subprocess import STDOUT
import sys
import select
import time
import os
from datetime import datetime
import logging
from ..core.config_manager import get_config
from ..core.exceptions import (
    CatalogError,
    InstallationError,
    UninstallationError,
    ManifestError,
    SystemCheckError
)
from .installation_validator import InstallationValidator

# Set up logging
logger = logging.getLogger(__name__)

# Constants
MUNKI_MSU_PATH = "/usr/local/munki/managedsoftwareupdate"
MANAGED_INSTALLS_DIR = "/Library/Managed Installs"
ALREADY_INSTALLED_MSG = "is already installed"
DOWNLOAD_FAILED_MSG = "download failed"
CONNECTION_ERROR_MSG = "connection error"
DOWNLOAD_ERROR_MSG = "download error"
WILL_BE_INSTALLED_MSG = "will be installed"
WILL_BE_UPGRADED_MSG = "will be upgraded"
PREFLIGHT_ABORT_MSG = "aborted by preflight script"
PREFLIGHT_FAILED_MSG = "preflight failed"


class MunkiInstaller:
    """Handles software installation and uninstallation via Munki."""

    def __init__(self):
        """Initialize MunkiInstaller."""
        self.current_catalog_item = None  # Store current item for EA generation

        # Initialize report_data if not already present (for standalone usage)
        # In CompositeTester, AutoUpdateTester.__init__() will have already set this
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

    def _is_preflight_abort(self, output_lines):
        """Check if managedsoftwareupdate was aborted by a preflight script.

        Args:
            output_lines: List of output lines from the process

        Returns:
            bool: True if the output indicates a preflight abort
        """
        preflight_patterns = [PREFLIGHT_ABORT_MSG, PREFLIGHT_FAILED_MSG]
        return any(
            any(pattern in str(line).lower() for pattern in preflight_patterns)
            for line in output_lines
        )

    def _log_preflight_abort(self, context):
        """Log a preflight abort warning for the given context.

        Args:
            context: Description of what was being attempted (e.g., 'catalog update')
        """
        print("   Auto Update preflight detected, continuing...")
        logger.info(f"Preflight abort detected during {context}, continuing")

    def _run_managedsoftwareupdate(self, args=None, action_type=""):
        """Run managedsoftwareupdate and capture output.

        Args:
            args: Additional arguments for managedsoftwareupdate (e.g., ["--installonly"])
            action_type: Type of action for output handling

        Returns:
            tuple: (process, output_lines) - the completed process and captured output
        """
        cmd = [MUNKI_MSU_PATH] + (args or [])

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        output_lines = self._handle_process_output(process, action_type)

        return process, output_lines

    def _update_catalog(self):
        """Run managedsoftwareupdate -v to update the catalog"""
        try:
            print("\nUpdating Munki catalog...")
            update_process, output_lines = self._run_managedsoftwareupdate(
                action_type="update"
            )

            if update_process.returncode != 0:
                if self._is_preflight_abort(output_lines):
                    self._log_preflight_abort("catalog update")
                    return True
                error_msg = "\n".join(
                    line for line in output_lines if "error" in str(line).lower()
                )
                raise CatalogError(f"Catalog update failed: {error_msg}")

            print("✅ Catalog update completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error updating catalog: {e}")
            print(f"❌ Error updating catalog: {e}")
            return False

    def _get_recent_munki_log_lines(self, max_lines=50):
        """
        Read the most recent lines from ManagedInstalls.log.

        Args:
            max_lines: Maximum number of lines to read from end of log

        Returns:
            list: Recent log lines
        """
        log_path = "/Library/Managed Installs/Logs/ManagedInstalls.log"
        try:
            if os.path.exists(log_path):
                result = subprocess.run(
                    ["tail", f"-n{max_lines}", log_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return result.stdout.strip().split('\n')
        except Exception as e:
            logger.debug(f"Could not read Munki log: {e}")
        return []

    def _download_packages(self):
        """
        Download packages using managedsoftwareupdate.

        Returns:
            list: Combined output from the download process

        Raises:
            InstallationError: If download fails
        """
        print("\n\nChecking for pending installs and downloading")
        print("=" * 60)

        check_process, check_output = self._run_managedsoftwareupdate(
            action_type="check"
        )

        if check_process.returncode != 0:
            if self._is_preflight_abort(check_output):
                self._log_preflight_abort("download check")
                return check_output
            else:
                error_msg = "\n".join(
                    line for line in check_output if "error" in str(line).lower()
                )
                logger.warning(f"managedsoftwareupdate check returned non-zero exit code: {check_process.returncode}")
                logger.warning(f"Error output: {error_msg}")

        # Check if download was successful and items are ready for installation
        download_successful = any(
            WILL_BE_INSTALLED_MSG in str(line).lower()
            or "run managedsoftwareupdate --installonly" in str(line).lower()
            for line in check_output
        )

        if not download_successful:
            # Check for specific reasons why installation isn't proceeding

            # First, check the Munki log for more details
            log_lines = self._get_recent_munki_log_lines()

            # Check if already installed (check both stdout and log)
            already_installed = [
                line for line in check_output
                if ALREADY_INSTALLED_MSG in str(line).lower()
            ]

            if not already_installed and log_lines:
                already_installed = [
                    line for line in log_lines
                    if ALREADY_INSTALLED_MSG in line.lower()
                ]

            if already_installed:
                # Extract the item name from the "already installed" message
                installed_items = []
                for line in already_installed:
                    # Parse lines like "GoogleChrome version 145.0.7632.46 (or newer) is already installed."
                    if ALREADY_INSTALLED_MSG in line.lower():
                        # Try to extract item name before "version"
                        parts = line.split("version")
                        if len(parts) > 0:
                            # Clean up timestamps and prefixes
                            item_name = parts[0].strip()
                            # Remove date/time prefix if present (e.g., "Feb 16 2026 14:23:56 +0000")
                            item_name = ' '.join([word for word in item_name.split() if not any(c.isdigit() for c in word) or len(word) > 10])
                            if item_name:
                                installed_items.append(item_name)

                if installed_items:
                    items_str = ", ".join(set(installed_items))  # Remove duplicates
                    raise InstallationError(f"Software already installed: {items_str}")
                else:
                    raise InstallationError("Software is already installed - no updates available")

            # Check for download errors
            download_errors = any(
                any(error in str(line).lower() for error in [
                    DOWNLOAD_ERROR_MSG, DOWNLOAD_FAILED_MSG, "network connection",
                    CONNECTION_ERROR_MSG, "timeout", "interrupted"
                ]) for line in check_output
            )

            if download_errors:
                raise InstallationError("Download failed - check network connection and try again")

            # Check for no matching items in catalog
            no_match_errors = [
                line for line in (check_output + log_lines)
                if any(msg in line.lower() for msg in [
                    "no items in managed_installs",
                    "nothing to install",
                    "no matching items"
                ])
            ]

            if no_match_errors:
                raise InstallationError("No matching items found in catalog - check item name and catalog configuration")

            # Generic error with suggestion to check logs
            raise InstallationError("No items available for installation - check /Library/Managed Installs/Logs/ManagedInstalls.log for details")

        print("   ✅ Download completed successfully")

        # Add a small delay to ensure download processes are complete
        import time
        time.sleep(2)

        return check_output

    def _analyze_package_dependencies(self):
        """Analyze packages for deprecated dependencies."""
        print("\nAnalyzing packages for deprecated dependencies...")
        try:
            from ..utils.package_analyzer import PackageAnalyzer
            package_analyzer = PackageAnalyzer()
            analysis_results = package_analyzer.analyze_packages_in_cache()

            if analysis_results and "error" not in analysis_results:
                self.report_data["package_analysis"] = analysis_results

                # Display summary
                packages_found = analysis_results.get("packages_found", 0)
                total_issues = analysis_results.get("total_issues", 0)
                critical_issues = analysis_results.get("critical_issues", 0)

                if total_issues > 0:
                    print(f"   ⚠️  Found {total_issues} deprecated dependency issue(s) in {packages_found} package(s)")
                    if critical_issues > 0:
                        print(f"   🚨 Found {critical_issues} critical issue(s) (Python 2 usage)")
                else:
                    print(f"   ✅ No deprecated dependencies found in {packages_found} package(s)")
            else:
                print("   ℹ️  Package analysis skipped or failed")
                if analysis_results and "error" in analysis_results:
                    print(f"   Error: {analysis_results['error']}")

        except Exception as e:
            print(f"   ⚠️  Package analysis failed: {e}")
            logger.warning(f"Package analysis failed: {e}")

    def _display_vt_result(self, result, item):
        """Display VirusTotal analysis result for a single file.

        Args:
            result: Analysis result dictionary
            item: Filename being analyzed
        """
        status = result.get("status", "unknown")

        if status == "clean":
            print(f"   ✅ {item}: Clean (0 detections)")
        elif status == "malicious":
            detections = result.get("scan_results", {}).get("detection_ratio", "unknown")
            print(f"   🚨 {item}: MALICIOUS ({detections} detections)")
        elif status == "suspicious":
            detections = result.get("scan_results", {}).get("detection_ratio", "unknown")
            print(f"   ⚠️  {item}: Suspicious ({detections} detections)")
        elif status == "too_large":
            size_mb = result.get("file_size_mb", "unknown")
            print(f"   📏 {item}: Too large for analysis ({size_mb} MB) - manual check required")
        elif status == "not_found":
            print(f"   ❓ {item}: Not found in VirusTotal database")
        elif status == "error":
            print(f"   ❌ {item}: Analysis failed - {result.get('message', 'unknown error')}")

    def _analyze_single_file_vt(self, vt_analyzer, item_path, item):
        """Analyze a single file with VirusTotal.

        Args:
            vt_analyzer: VirusTotalAnalyzer instance
            item_path: Full path to file
            item: Filename

        Returns:
            tuple: (result dict, should_continue bool)
        """
        print(f"   🔍 Analyzing {item} for malware...")
        try:
            result = vt_analyzer.analyze_file(item_path)
            return result, True
        except Exception as e:
            error_str = str(e)
            logger.error(f"VirusTotal analysis error for {item}: {e}")

            # Check if it's a network connectivity issue
            if any(err in error_str for err in [
                "nodename nor servname provided",
                "Name or service not known",
                "[Errno 8]"
            ]):
                print("   ⚠️  Cannot reach VirusTotal API - network or DNS issue")
                print("   💡 Skipping VirusTotal analysis (continue without malware scan)")
                return None, False  # Signal to stop processing

            return {
                "status": "error",
                "error": str(e),
                "file_name": item
            }, True

    def _calculate_vt_summary(self, vt_results):
        """Calculate VirusTotal analysis summary statistics.

        Args:
            vt_results: List of analysis results

        Returns:
            dict: Summary statistics
        """
        return {
            "total_files": len(vt_results),
            "results": vt_results,
            "clean_files": len([r for r in vt_results if r.get("status") == "clean"]),
            "malicious_files": len([r for r in vt_results if r.get("status") == "malicious"]),
            "suspicious_files": len([r for r in vt_results if r.get("status") == "suspicious"]),
            "error_files": len([r for r in vt_results if r.get("status") == "error"]),
            "manual_check_required": len([r for r in vt_results if r.get("requires_manual_check")])
        }

    def _print_vt_summary(self, vt_results):
        """Print VirusTotal analysis summary.

        Args:
            vt_results: List of analysis results
        """
        total_files = len(vt_results)
        malicious_count = len([r for r in vt_results if r.get("status") == "malicious"])
        suspicious_count = len([r for r in vt_results if r.get("status") == "suspicious"])

        if malicious_count > 0:
            print(f"   🚨 MALWARE DETECTED: {malicious_count} malicious file(s) found!")
        elif suspicious_count > 0:
            print(f"   ⚠️  Suspicious content detected: {suspicious_count} file(s)")
        else:
            print(f"   ✅ All {total_files} file(s) passed malware analysis")

    def _analyze_virustotal(self):
        """Analyze packages for malware with VirusTotal."""
        print("\nAnalyzing packages for malware with VirusTotal...")
        try:
            from ..security.virustotal_analyzer import VirusTotalAnalyzer

            vt_analyzer = VirusTotalAnalyzer(
                submit_new=True,
                timeout=300  # 5 minutes
            )

            # Find PKG files in the Munki cache
            cache_dir = "/Library/Managed Installs/Cache"
            vt_results = []

            if os.path.exists(cache_dir):
                for item in os.listdir(cache_dir):
                    item_path = os.path.join(cache_dir, item)
                    if os.path.isfile(item_path) and (item.lower().endswith('.pkg') or item.lower().endswith('.dmg')):
                        result, should_continue = self._analyze_single_file_vt(vt_analyzer, item_path, item)

                        if result is None:
                            break  # Network error, stop processing

                        vt_results.append(result)
                        self._display_vt_result(result, item)

                        if not should_continue:
                            break

            # Store results for reporting
            if vt_results:
                self.report_data["virustotal_analysis"] = self._calculate_vt_summary(vt_results)
                self._print_vt_summary(vt_results)

        except Exception as e:
            print(f"   ⚠️  VirusTotal analysis failed: {e}")
            logger.warning(f"VirusTotal analysis failed: {e}")

    def _analyze_threatlabs(self):
        """Analyze binaries with ThreatLabs."""
        print("\nAnalyzing binaries with ThreatLabs...")
        try:
            config = get_config()
            if not config.is_threatlabs_enabled():
                print("   ℹ️  ThreatLabs scanning disabled in config - skipping binary analysis")
                logger.info("ThreatLabs scanning skipped - disabled in config")
                return

            from ..security.threatlabs_scanner import ThreatLabsScanner
            from ..utils.binary_extractor import BinaryExtractor

            threatlabs = ThreatLabsScanner()

            if not threatlabs.is_available():
                print("   ℹ️  ThreatLabs API key not configured - skipping binary analysis")
                logger.info("ThreatLabs scanning skipped - no API key")
                return

            # Extract binaries from packages
            extractor = BinaryExtractor()
            all_binaries = []

            cache_dir = "/Library/Managed Installs/Cache"
            if os.path.exists(cache_dir):
                for item in os.listdir(cache_dir):
                    item_path = os.path.join(cache_dir, item)
                    if os.path.isfile(item_path) and (item.lower().endswith('.pkg') or item.lower().endswith('.dmg')):
                        print(f"   📦 Extracting binaries from {item}...")
                        binaries = extractor.extract_binaries(item_path)
                        all_binaries.extend(binaries)
                        print(f"      Found {len(binaries)} Mach-O binary(ies)")
                        # Log detail about what was found
                        if binaries and logger.isEnabledFor(logging.DEBUG):
                            for b in binaries:
                                logger.debug(f"      - {b['name']} ({b.get('type', 'unknown type')}) in {b.get('relative_path', 'unknown path')}")

            if all_binaries:
                # Submit Mach-O executables to ThreatLabs for analysis
                # Use otool filetype to identify true executables vs libraries/bundles
                # Only EXECUTE filetype binaries are submitted (excludes DYLIB, BUNDLE, etc.)
                # This prevents wasting API calls on files ThreatLabs can't analyze (returns HTTP 415)

                scannable_binaries = []
                excluded_count = 0

                for b in all_binaries:
                    binary_type = b.get('type', '').lower()
                    name = b['name']
                    filetype = b.get('filetype')

                    # Verify it's actually a Mach-O binary
                    if 'mach-o' not in binary_type:
                        logger.warning(f"Non-Mach-O file found in extraction: {name} ({binary_type})")
                        continue

                    # Only submit EXECUTE filetype - excludes DYLIB, BUNDLE, and other non-executable types
                    # Use otool filetype determination (more reliable than file command or extension checking)
                    if filetype != 'EXECUTE':
                        logger.debug(f"Excluding non-executable (filetype: {filetype}): {name}")
                        excluded_count += 1
                        continue

                    scannable_binaries.append(b)
                    logger.debug(f"Including executable: {name} (filetype: {filetype})")

                if not scannable_binaries:
                    print("   ℹ️  No executable binaries found (libraries/bundles/plugins excluded)")
                else:
                    print(f"   🔍 Submitting {len(scannable_binaries)} binary(ies) to ThreatLabs...")
                    if excluded_count > 0:
                        logger.info(f"Note: {excluded_count} non-executable(s) excluded (libraries/bundles/plugins not supported by ThreatLabs)")
                    if len(scannable_binaries) + excluded_count != len(all_binaries):
                        logger.info(f"Note: {len(all_binaries) - len(scannable_binaries) - excluded_count} non-Mach-O files excluded")

                scan_results = threatlabs.scan_binaries(scannable_binaries, max_submissions=10) if scannable_binaries else {'total_binaries': 0, 'submitted': 0, 'results': []}
                summary = threatlabs.get_summary(scan_results)

                # Store results for reporting
                self.report_data["threatlabs_analysis"] = {
                    "summary": summary,
                    "results": scan_results
                }

                # Display summary
                if summary['malicious'] > 0:
                    print(f"   🚨 THREATS DETECTED: {summary['malicious']} malicious binary(ies)!")
                elif summary['suspicious'] > 0:
                    print(f"   ⚠️  {summary['suspicious']} suspicious binary(ies) detected")
                elif summary['too_large'] > 0 and summary['clean'] == 0 and summary['unsupported'] == 0:
                    print(f"   ⚠️  {summary['too_large']} binary(ies) too large for analysis - could not scan")
                else:
                    # Show comprehensive summary
                    if summary['clean'] > 0:
                        print(f"   ✅ {summary['clean']} binary(ies) analyzed - all clean")
                    if summary['too_large'] > 0:
                        print(f"   ⚠️  {summary['too_large']} binary(ies) skipped (too large for analysis)")
                    if summary['unsupported'] > 0:
                        print(f"   ℹ️  {summary['unsupported']} binary(ies) skipped (file type not supported by ThreatLabs API)")
                    if summary['clean'] == 0 and summary['too_large'] == 0 and summary['unsupported'] == 0:
                        print("   ℹ️  No binaries successfully analyzed")
            else:
                print("   ℹ️  No binaries extracted for analysis")

            # Cleanup temporary files
            extractor.cleanup()

        except Exception as e:
            print(f"   ⚠️  ThreatLabs analysis failed: {e}")
            logger.warning(f"ThreatLabs analysis failed: {e}")

    def _check_installation_success(self, combined_output, item_name):
        """Check if installation indicators suggest success.

        Args:
            combined_output: Combined output from check and install phases
            item_name: Name of the item being installed

        Returns:
            bool: True if success indicators found
        """
        return any(
            any(success_indicator in line.lower() for success_indicator in [
                "successfully installed",
                "the software was successfully installed",
                "installation successful",
                "installed successfully"
            ])
            or ("copying" in line.lower() and item_name.lower() in line.lower())
            or ("installing" in line.lower() and item_name.lower() in line.lower())
            for line in combined_output
        )

    def _extract_package_info(self, combined_output):
        """Extract package info from installation output.

        Args:
            combined_output: Combined output from check and install phases
        """
        for line in combined_output:
            if "will be installed or upgraded" in line.lower():
                pkg_line = next(
                    (line_item for line_item in combined_output if line_item.strip().startswith("+")),
                    ""
                )
                if pkg_line:
                    pkg_name = pkg_line.strip("+ ").strip()
                    self.report_data['install_details'].append(f"Package to be installed: {pkg_name}")
                break

    def _check_installation_failure(self, combined_output):
        """Check if installation failed and collect failure details.

        Args:
            combined_output: Combined output from check and install phases

        Returns:
            tuple: (installation_failed bool, failure_details list)
        """
        installation_failed = any(
            any(failure_indicator in line.lower() for failure_indicator in [
                "install of",
                "failed with return code",
                "installation failed",
                "install failed",
                "error occurred during installation",
                "installation was not successful"
            ]) and any(fail_keyword in line.lower() for fail_keyword in ["failed", "error"])
            for line in combined_output
        )

        failure_details = []
        for line in combined_output:
            line_str = str(line).lower()
            if ("failed with return code" in line_str
                    or ("install of" in line_str and "failed" in line_str)):
                failure_details.append(str(line))
                print(f"   ❌ {line}")

        return installation_failed, failure_details

    def _handle_installation_failure(self, item_name, start_time, failure_details):
        """Handle installation failure by logging and raising error.

        Args:
            item_name: Name of the item being installed
            start_time: Installation start time
            failure_details: List of failure messages

        Raises:
            InstallationError: Always raised after logging
        """
        end_time = datetime.now()
        duration = InstallationValidator.format_installation_duration(start_time, end_time)

        error_message = f"Installation failed for {item_name}"
        if failure_details:
            error_message += f". Details: {'; '.join(failure_details)}"

        # Log the failure
        self.report_data['install_details'].append(f"Installation failed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.report_data['install_details'].append(f"Installation duration: {duration}")
        for detail in failure_details:
            self.report_data['install_details'].append(f"Failure: {detail}")

        print("\n❌ Installation failed!")
        print(f"Duration: {duration}")
        if failure_details:
            print("Failure details:")
            for detail in failure_details:
                print(f"   {detail}")

        raise InstallationError(error_message)

    def _log_installation_success(self, combined_output, installation_occurred):
        """Log installation success messages.

        Args:
            combined_output: Combined output from check and install phases
            installation_occurred: Whether installation indicators were found
        """
        success_found = False
        for line in combined_output:
            if line and (
                "successfully installed" in str(line).lower()
                or "The software was successfully installed" in str(line)
            ):
                self.report_data['install_details'].append(str(line))
                print(f"   ✅ {line}")
                success_found = True

        if not success_found and not installation_occurred:
            print("   ⚠️  No clear success indicators found, but no explicit failures detected")

        print("   ✅ Installation process completed")

    def _execute_installation(self, item_name, check_output, start_time):
        """
        Execute the actual installation using managedsoftwareupdate --installonly.

        Args:
            item_name: Name of the item being installed
            check_output: Output from the download/check phase
            start_time: Installation start time

        Raises:
            InstallationError: If installation fails
        """
        print("\n\nInstalling software")
        print("=" * 60)
        install_process, install_output = self._run_managedsoftwareupdate(
            args=["--installonly"], action_type="install"
        )

        # Combine outputs from both check and install phases
        combined_output = [str(line) for line in (check_output + install_output) if line is not None]

        # Check for success and extract info
        installation_occurred = self._check_installation_success(combined_output, item_name)
        self._extract_package_info(combined_output)

        # Handle non-zero return code
        if install_process.returncode != 0:
            if self._is_preflight_abort(install_output):
                self._log_preflight_abort("installation")
            else:
                error_msg = "\n".join(
                    str(line) for line in combined_output
                    if line and "error" in str(line).lower()
                )
                logger.warning(f"managedsoftwareupdate returned non-zero exit code: {install_process.returncode}")
                logger.warning(f"Error output: {error_msg}")

        # Check for installation failure
        installation_failed, failure_details = self._check_installation_failure(combined_output)

        # Handle failure case
        if installation_failed or failure_details:
            self._handle_installation_failure(item_name, start_time, failure_details)

        # Log success
        self._log_installation_success(combined_output, installation_occurred)

    def _wait_for_user_testing(self):
        """Wait for user to test the application and press Enter."""
        print("\n✅ Installation process completed successfully")

        # Continue monitoring until user explicitly stops it
        print(
            "\n❗❗RUN THE APPLICATION and accept any configuration notifications..."
            " Monitoring for security and system events."
            " Press Enter when ready to proceed with additional security scans..."
        )
        try:
            # Keep checking for events until user presses Enter
            import time
            event_check_counter = 0
            while True:
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    input()  # Wait for Enter key
                    break

                # Check for new security events every 5 seconds
                event_check_counter += 1
                if event_check_counter >= 50:  # 50 * 0.1 = 5 seconds
                    self.check_monitoring_events()
                    event_check_counter = 0

                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user")
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")

    def _run_post_install_knockknock(self):
        """Run post-installation KnockKnock scan and comparison."""
        if self.report_data.get('knockknock_available') and hasattr(self, 'knockknock_scanner'):
            print("\nRunning KnockKnock Post-Installation Analysis")
            print("=" * 60)
            if self.knockknock_scanner.run_post_install_scan():
                # Compare scans to find new/modified items
                comparison = self.knockknock_scanner.compare_scans()

                # Add results to report data
                self.report_data['knockknock_results'] = {
                    'summary': self.knockknock_scanner.get_scan_summary(),
                    'comparison': comparison
                }

                # Print summary
                print("\n📊 KnockKnock Analysis Results:")
                print(f"   • New persistence items: {comparison['new_count']}")
                print(f"   • Modified items: {comparison['modified_count']}")
                print(f"   • Removed items: {comparison['removed_count']}")

                if comparison['new_count'] > 0:
                    print(f"\n   ⚠️  {comparison['new_count']} new persistence item(s) detected!")
                    print("   See report for detailed VirusTotal analysis")
            else:
                logger.warning("Post-installation KnockKnock scan failed")
                self.report_data['knockknock_results'] = {
                    'error': 'Post-installation scan failed'
                }

    def _run_code_signing_check(self, item_name):
        """Run code signing check and generate configuration profiles."""
        print("\nReady to check application code signing and generate configuration profiles.")
        try:
            # Initialize empty report data if needed
            if not hasattr(self, 'report_data') or self.report_data is None:
                self.report_data = {}

            # Call the code signing check which includes drag-and-drop profile generation
            output_dir = getattr(self, 'output_directory', None)
            self._check_code_signing(munki_item_name=item_name, output_directory=output_dir)

            # Configuration profile data is already in self.report_data
            if 'configuration_profiles' in self.report_data:
                print("\n✅ Configuration profile generation completed")
            else:
                # No profiles were generated
                self.report_data['configuration_profiles'] = {
                    'generated_profiles': [],
                    'profile_summary': "## Configuration Profiles\n\nNo applications were analyzed for configuration profiles.\n",
                    'profile_statistics': {'total_profiles': 0, 'total_applications': 0},
                    'saved_files': []
                }

        except Exception as e:
            import traceback
            logger.error(f"Error in code signing verification: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            print(f"❌ Error in code signing verification: {e}")
            print("\n🔍 Detailed traceback:")
            traceback.print_exc()
            # Don't fail the entire installation if code signing check fails
            self.report_data['configuration_profiles'] = {
                'error': str(e),
                'generated_profiles': [],
                'profile_summary': f"## Configuration Profiles\n\nProfile generation failed: {e}\n",
                'profile_statistics': {'total_profiles': 0, 'total_applications': 0},
                'saved_files': []
            }

    def install_and_test(self, item_name):
        """Install and test application using Munki manifest"""
        try:
            print(f"\n\nStarting installation process for {item_name}\n")
            start_time = datetime.now()

            # Save security tool states before starting
            print("\nSaving security tool states...")
            self._manage_security_tool_states(action="save")

            # Get catalog item and validate
            catalog_items = self._get_catalog_items(item_name)
            if not catalog_items:
                raise CatalogError(f"No catalog items found for {item_name}")

            # Store the catalog item for later use (EA generation)
            self.current_catalog_item = catalog_items[0]

            # Validate the first matching catalog item
            validation_results = self._validate_catalog_item(catalog_items[0])
            self.report_data['catalog_validation'] = validation_results

            # Print validation results
            print("\nCatalog Item Validation:")
            for result in validation_results:
                print(f"  {result}")
            print()
            self.report_data['install_details'].append(
                f"Installation started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}"
            )

            # Run initial system checks
            if not self._run_system_checks():
                raise SystemCheckError("Failed to complete initial system checks")

            # Run KnockKnock baseline scan before installation
            self.knockknock_scanner = InstallationValidator.setup_knockknock_scanner(
                self.report_data
            )

            # Start security monitoring before installation
            self.start_security_monitoring()

            # Update manifest for installation
            print("\nUpdating manifest for installation")
            print("=" * 60)

            if not self._update_manifest(item_name, "install"):
                raise ManifestError("Failed to update manifest for installation")
            print("   ✅ Manifest updated successfully")

            # Download packages
            check_output = self._download_packages()

            # Analyze packages for deprecated dependencies
            self._analyze_package_dependencies()

            # VirusTotal malware analysis
            self._analyze_virustotal()

            # ThreatLabs binary analysis
            self._analyze_threatlabs()

            # Execute installation
            self._execute_installation(item_name, check_output, start_time)

            end_time = datetime.now()
            self.report_data['install_details'].append(
                f"Installation completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            self.report_data['install_details'].append(
                f"Installation duration: {InstallationValidator.format_installation_duration(start_time, end_time)}"
            )

            # Add loop install check here
            if not self._check_for_loop_installs(item_name):
                raise InstallationError("Installation completed but loop install check failed")

            # Wait for user testing
            self._wait_for_user_testing()

            # Stop monitoring and collect events
            self.stop_security_monitoring()

            # Run post-installation KnockKnock scan
            self._run_post_install_knockknock()

            # Run security scans
            self.run_security_scans()

            # Run code signing check and generate configuration profiles
            self._run_code_signing_check(item_name)

            return True

        except Exception as e:
            logger.error(f"Error during installation/testing: {e}")
            print(f"\n❌ Installation process failed: {e}")
            self.report_data['install_details'].append(f"Installation failed: {str(e)}")

            # Make sure to stop monitoring on error
            try:
                self.stop_security_monitoring()
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {cleanup_error}")
            return False

        finally:
            # Ensure security monitoring is stopped
            try:
                if hasattr(self, 'monitoring_processes'):
                    self.stop_security_monitoring()
            except Exception as cleanup_error:
                logger.error(f"Error during final cleanup: {cleanup_error}")

    def uninstall_app(self, item_name):
        """Uninstall application using Munki manifest"""
        try:
            print(f"\n\nStarting uninstallation process for {item_name}\n")
            start_time = datetime.now()

            # Start security monitoring before uninstallation
            self.start_security_monitoring()

            # Update manifest for uninstallation
            print("\nUpdating manifest for uninstallation")
            print("=" * 60)

            if not self._update_manifest(item_name, "uninstall"):
                raise ManifestError("Failed to update manifest for uninstallation")
            print("   ✅ Manifest updated successfully")

            # Run managedsoftwareupdate to check for changes
            print("\nChecking for software updates")
            print("=" * 60)

            check_process, check_output = self._run_managedsoftwareupdate(
                action_type="check"
            )

            if check_process.returncode != 0:
                if self._is_preflight_abort(check_output):
                    self._log_preflight_abort("uninstall check")
                else:
                    error_msg = "\n".join(
                        line for line in check_output if "error" in str(line).lower()
                    )
                    raise UninstallationError(f"Update check failed: {error_msg}")
            else:
                print("   ✅ Software update check completed")

            # Run managedsoftwareupdate to apply changes
            print("\n\nRunning uninstallation")
            print("=" * 60)

            uninstall_process, uninstall_output = self._run_managedsoftwareupdate(
                args=["--installonly"], action_type="uninstall"
            )

            # Check for various conditions in the output
            nothing_to_remove = any(
                "Nothing to install or remove" in line
                for line in uninstall_output
            )
            uninstall_failed = any("failed" in line.lower() for line in uninstall_output)

            # Collect successful removal messages
            for line in uninstall_output:
                if "successfully removed" in line.lower():
                    self.report_data["uninstall_results"].append(line)

            # Check for uninstallation success
            if uninstall_process.returncode != 0 or uninstall_failed:
                if self._is_preflight_abort(uninstall_output):
                    self._log_preflight_abort("uninstallation")
                else:
                    error_msg = "\n".join(uninstall_output)
                    raise UninstallationError(f"Uninstallation failed: {error_msg}")
            elif nothing_to_remove:
                raise UninstallationError(
                    f"Nothing to remove - {item_name} may not be installed or "
                    "not removable via Munki"
                )

            end_time = datetime.now()
            self.report_data["uninstall_results"].append(
                f"Successfully uninstalled {item_name} at {end_time.strftime('%H:%M:%S')}"
            )
            self.report_data["uninstall_results"].append(
                f"Uninstallation duration: {InstallationValidator.format_installation_duration(start_time, end_time)}"
            )

            print(
                "\nMonitoring for uninstall security events. "
                "Press Enter when ready to proceed..."
            )
            try:
                while True:
                    if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                        line = input()
                        break
                    time.sleep(0.1)
            except KeyboardInterrupt:
                print("\nMonitoring interrupted by user")

            self.stop_security_monitoring()

            # Add loop uninstall check here
            if not self._check_for_loop_uninstalls(item_name):
                raise UninstallationError("Uninstallation completed but loop uninstall check failed")

            print("\n✅ Uninstallation process completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error during uninstallation: {e}")
            print(f"\n❌ Uninstallation process failed: {e}")
            self.report_data["uninstall_results"].append(
                f"Failed to uninstall {item_name}: {str(e)}"
            )

            # Make sure to stop monitoring on error
            self.stop_security_monitoring()
            return False

    _DOWNLOAD_ERROR_PHRASES = [
        DOWNLOAD_ERROR_MSG, DOWNLOAD_FAILED_MSG,
        "network connection was lost", CONNECTION_ERROR_MSG, "timeout",
    ]

    @staticmethod
    def _is_download_error(line_str):
        """Return True if *line_str* contains a download-error indicator."""
        line_lower = line_str.lower()
        return any(phrase in line_lower
                   for phrase in MunkiInstaller._DOWNLOAD_ERROR_PHRASES)

    @staticmethod
    def _strip_arrow_prefix(text):
        """Strip a leading ``→`` or ``->`` arrow from *text*."""
        for arrow in ("→ ", "-> "):
            if text.startswith(arrow):
                return text[len(arrow):]
        return text

    @staticmethod
    def _is_section_header(line_lower, section_headers, item_prefix):
        """Return True if *line_lower* marks a pending-items section."""
        if any(phrase in line_lower for phrase in section_headers):
            return True
        # For installs, "--installonly" also confirms queued items
        return (item_prefix == "+"
                and "--installonly" in line_lower
                and "install the downloaded" in line_lower)

    @staticmethod
    def _detect_pending_item(check_output, item_name, section_headers,
                             item_prefix, action_keywords):
        """Parse Munki output to detect whether *item_name* is still pending.

        Args:
            check_output: Lines of ``managedsoftwareupdate`` output.
            item_name: The Munki item to look for.
            section_headers: Lowercase phrases that mark the start of the
                pending-items section (e.g. ``["will be removed"]``).
            item_prefix: Single character (``"+"`` or ``"-"``) used by Munki
                to prefix pending items.
            action_keywords: Dict with ``"primary"`` (exact-case keyword like
                ``"Need to install"``) and ``"secondary"`` (lowercase phrases
                for an ``any()`` check).

        Returns:
            dict with keys ``found_item``, ``needs_action``,
            ``action_message``, ``has_download_errors``, ``details``.
        """
        result = {
            "found_item": False,
            "needs_action": False,
            "action_message": None,
            "has_download_errors": False,
            "details": [],
        }

        pending_section = False

        for line in check_output:
            line_str = str(line)
            line_lower = line_str.lower()

            if MunkiInstaller._is_download_error(line_str):
                result["has_download_errors"] = True
                result["details"].append(
                    f"Download error detected: {line_str.strip()}"
                )

            if MunkiInstaller._is_section_header(
                    line_lower, section_headers, item_prefix):
                pending_section = True

            if item_name not in line_str:
                continue

            result["found_item"] = True
            result["details"].append(f"Found reference: {line_str.strip()}")

            # Explicit keyword match on the same line
            if (action_keywords["primary"] in line_str
                    or any(kw in line_lower
                           for kw in action_keywords["secondary"])):
                result["needs_action"] = True
                result["action_message"] = line_str.strip()
                break

            # Munki lists pending items with a prefix character after the
            # section header (e.g. "→ + OmniFocus-4.8.8").
            stripped = MunkiInstaller._strip_arrow_prefix(line_str.strip())
            if stripped.startswith(item_prefix) and pending_section:
                result["needs_action"] = True
                result["action_message"] = line_str.strip()
                break

        return result

    # ------------------------------------------------------------------
    # Loop-check helpers
    # ------------------------------------------------------------------

    def _check_for_loop_uninstalls(self, item_name):
        """Check if the item needs to be uninstalled again after uninstallation"""
        return self._run_loop_check(
            item_name,
            action="uninstall",
            label="uninstall",
            report_key="loop_uninstall_test",
            section_headers=["will be removed", "will be uninstalled"],
            item_prefix="-",
            action_keywords={
                "primary": "Need to remove",
                "secondary": [
                    "will be removed", "will be uninstalled",
                    "pending removal", "pending uninstall",
                ],
            },
            error_class=UninstallationError,
            check_detail="✅ Performed post-uninstall looping uninstallation check",
            no_loop_detail="✅ No re-uninstallation required",
        )

    def _check_for_loop_installs(self, item_name):
        """Check if the item needs to be reinstalled after installation"""
        return self._run_loop_check(
            item_name,
            action="install",
            label="install",
            report_key="loop_install_test",
            section_headers=["will be installed or upgraded"],
            item_prefix="+",
            action_keywords={
                "primary": "Need to install",
                "secondary": [
                    "will be installed", "will be upgraded",
                    "pending install", "pending upgrade",
                ],
            },
            error_class=InstallationError,
            check_detail="✅ Performed post-install looping installation check",
            no_loop_detail="✅ No reinstallation required",
        )

    def _run_loop_check(self, item_name, *, action, label, report_key,
                        section_headers, item_prefix, action_keywords,
                        error_class, check_detail, no_loop_detail):
        """Shared implementation for install/uninstall loop checks."""
        try:
            print(f"\nChecking for {label} loops")
            print("=" * 60)

            loop_test_results = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "passed",
                "details": [],
            }

            # Update manifest for the check
            if not self._update_manifest(item_name, action):
                error_msg = "Failed to update manifest for loop check"
                loop_test_results["status"] = "error"
                loop_test_results["details"].append(error_msg)
                raise ManifestError(error_msg)

            # Run managedsoftwareupdate to check status
            check_process = subprocess.Popen(
                [MUNKI_MSU_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            check_output = self._handle_process_output(check_process, "check")
            loop_test_results["details"].append(check_detail)

            # Parse output for pending items
            parsed = self._detect_pending_item(
                check_output, item_name, section_headers,
                item_prefix, action_keywords,
            )
            loop_test_results["details"].extend(parsed["details"])

            if parsed["needs_action"]:
                if parsed["has_download_errors"]:
                    loop_test_results["details"].append(
                        f"✅ Needs {label} due to download errors - not a loop"
                    )
                    loop_test_results["details"].append(no_loop_detail)
                    self.report_data[report_key] = loop_test_results
                    print(f"✅ {label.capitalize()} needed due to download errors - not a loop")
                else:
                    loop_test_results["status"] = "failed"
                    error_msg = f"{label.capitalize()} loop detected: {parsed['action_message']}"
                    loop_test_results["details"].append(f"⚠️ {error_msg}")
                    self.report_data[report_key] = loop_test_results

                    print(f"\n{label.capitalize()} Loop Details:")
                    for detail in loop_test_results["details"]:
                        print(f"   {detail}")
                    print()

                    raise error_class(error_msg)

            # No loop detected
            loop_test_results["details"].append(no_loop_detail)
            self.report_data[report_key] = loop_test_results
            print(f"✅ No {label} loops detected")

            # Clean up manifest — remove item so it returns to default state
            self._cleanup_manifest_item(item_name)

            print("\nLoop Check Details:")
            for detail in loop_test_results["details"]:
                print(f"   {detail}")
            print()

            return True

        except Exception as e:
            logger.error(f"{label.capitalize()} loop check failed: {e}")
            print(f"❌ {label.capitalize()} loop check failed: {e}")
            if "loop_test_results" not in locals():
                self.report_data[report_key] = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "error",
                    "details": [str(e)],
                }
            return False
