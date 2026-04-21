# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Shared validation logic for both Munki and manual installations.

This module provides common validation functions to eliminate code
duplication between installer.py and manual_installer.py.
"""

import logging

logger = logging.getLogger(__name__)


class InstallationValidator:
    """Shared validation methods for installation workflows."""

    @staticmethod
    def setup_knockknock_scanner(report_data):
        """
        Initialize and run KnockKnock baseline scan.

        KnockKnock v4.0.0+ includes Shell Configuration Files plugin,
        VirusTotal v3 API, and improved Full Disk Access detection.

        KnockKnock v4.0.3+ provides enhanced BTM enumeration for better
        persistence mechanism detection.

        Args:
            report_data: Dictionary to store report information

        Returns:
            Instance of KnockKnockScanner or None
        """
        print("\nKnockKnock Security Scanning (Baseline)")
        print("=" * 60)

        from ..security.knockknock_scanner import KnockKnockScanner
        knockknock_scanner = KnockKnockScanner()

        if knockknock_scanner.is_available():
            knockknock_scanner.run_baseline_scan()
            report_data['knockknock_available'] = True
            return knockknock_scanner
        else:
            print("\n⚠️  KnockKnock not installed - skipping persistence analysis")
            logger.info("KnockKnock not available, skipping persistence scanning")
            report_data['knockknock_available'] = False
            return None

    @staticmethod
    def run_knockknock_comparison(knockknock_scanner, report_data):
        """
        Run post-installation KnockKnock scan and comparison.

        KnockKnock v4.0.2+ uses refactored comparison logic (#45) for
        improved detection of persistence changes.

        Args:
            knockknock_scanner: Instance of KnockKnockScanner
            report_data: Dictionary to store report information

        Returns:
            Comparison results or None
        """
        if not report_data.get('knockknock_available') or not knockknock_scanner:
            return None

        print("\nKnockKnock Post-Installation Scan")
        print("=" * 60)
        comparison = knockknock_scanner.run_comparison_scan()

        if comparison and comparison.get('new_count', 0) > 0:
            report_data['knockknock_results'] = {
                'summary': knockknock_scanner.get_scan_summary(),
                'comparison': comparison
            }
            print(f"\n   ⚠️  {comparison['new_count']} new persistence item(s) detected!")
            print("   See report for detailed VirusTotal analysis")
            return comparison
        else:
            logger.warning("Post-installation KnockKnock scan failed")
            report_data['knockknock_results'] = {
                'error': 'Post-installation scan failed'
            }
            return None

    @staticmethod
    def validate_installer_file(installer_path):
        """
        Validate that installer file exists and has appropriate permissions.

        Args:
            installer_path: Path to installer file

        Returns:
            Tuple of (is_valid: bool, error_message: str)
        """
        import os

        if not os.path.exists(installer_path):
            return False, f"Installer file not found: {installer_path}"

        if not os.access(installer_path, os.R_OK):
            return False, f"Installer file is not readable: {installer_path}"

        # Check file size (warn if too large)
        file_size = os.path.getsize(installer_path)
        file_size_mb = file_size / (1024 * 1024)

        if file_size_mb > 1000:  # > 1GB
            logger.warning(f"Large installer file detected: {file_size_mb:.1f} MB")

        return True, ""

    @staticmethod
    def get_installer_type(installer_path):
        """
        Determine the type of installer based on file extension.

        Args:
            installer_path: Path to installer file

        Returns:
            Tuple of (file_type: str, is_pkg: bool)
        """
        import os

        # Common archive extensions that need special handling
        ARCHIVE_EXTENSIONS = [
            '.tar.gz', '.tar.bz2', '.tar.xz',
            '.tgz', '.tbz2', '.txz'
        ]

        full_name = os.path.basename(installer_path).lower()
        file_ext = os.path.splitext(installer_path)[1].lower()

        # Check for multi-extension archives
        for archive_ext in ARCHIVE_EXTENSIONS:
            if full_name.endswith(archive_ext):
                return archive_ext, False

        is_pkg = file_ext == '.pkg'
        return file_ext or 'no extension', is_pkg

    @staticmethod
    def format_installation_duration(start_time, end_time):
        """
        Format installation duration in a human-readable format.

        Args:
            start_time: datetime object for start
            end_time: datetime object for end

        Returns:
            Formatted duration string
        """
        duration = end_time - start_time
        total_seconds = int(duration.total_seconds())

        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
