# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
KnockKnock Scanner Module

Integrates KnockKnock scanning into the security workflow to detect persistence mechanisms
before and after software installation.
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Dict, Optional, Any
from ..core.config_manager import get_config

logger = logging.getLogger(__name__)


class KnockKnockScanner:
    """
    KnockKnock integration for detecting persistence mechanisms.

    Features:
    - Pre-installation baseline scan
    - Post-installation comparison
    - VirusTotal integration for detected items
    - Detailed reporting of changes

    KnockKnock v4.0.0+ Features:
    - Shell Configuration Files plugin - Detects persistence in ~/.zshrc, etc.
    - VirusTotal v3 API with user-provided keys (#31, #39, #17)
    - Improved command line scan logic and output
    - Better Full Disk Access detection
    - Improved JSON export format (#42)

    KnockKnock v4.0.2+:
    - Refactored/improved 'Compare Scan(s)' logic (#45)

    KnockKnock v4.0.3+:
    - Improved BTM (Background Task Management) enumeration (#23)
    - VirusTotal submission defaults to off (#46)
    - UI improvements
    """

    KNOCKKNOCK_PATH = "/Applications/KnockKnock.app/Contents/MacOS/KnockKnock"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize KnockKnock scanner.

        Args:
            api_key: VirusTotal API key (uses config file if None)
        """
        config = get_config()
        self.api_key = api_key or config.get_virustotal_key()
        self.baseline_scan = None
        self.post_install_scan = None

    def is_available(self) -> bool:
        """Check if KnockKnock is installed and accessible."""
        return os.path.exists(self.KNOCKKNOCK_PATH) and os.access(self.KNOCKKNOCK_PATH, os.X_OK)

    def run_scan(self, skip_virustotal: bool = False) -> Optional[Dict[str, Any]]:
        """
        Run a KnockKnock scan.

        KnockKnock v4.0.0+ includes Shell Configuration Files plugin for
        detecting persistence in ~/.zshrc and similar files, and uses the
        VirusTotal v3 API with improved handling.

        KnockKnock v4.0.3+ provides improved BTM enumeration and enhanced
        command-line scan output.

        Args:
            skip_virustotal: If True, don't query VirusTotal (for faster baseline scans)

        Returns:
            Dict containing scan results, or None if scan failed
        """
        if not self.is_available():
            logger.error("KnockKnock not found at expected path")
            return None

        try:
            # Build command
            cmd = [
                self.KNOCKKNOCK_PATH,
                "-whosthere",
                "-verbose",
                "-pretty"
            ]

            # Add VirusTotal parameters
            if not skip_virustotal:
                cmd.extend(["-key", self.api_key])
            else:
                cmd.append("-skipVT")

            # Don't include Apple items by default (can be noisy)
            # Add "-apple" flag if you want to include trusted platform items

            logger.info(f"Running KnockKnock scan (VirusTotal: {'enabled' if not skip_virustotal else 'disabled'})")
            print("🔍 Running KnockKnock scan...")

            # Run KnockKnock with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                logger.error(f"KnockKnock scan failed with return code {result.returncode}")
                logger.error(f"STDERR: {result.stderr}")
                logger.error(f"STDOUT: {result.stdout}")
                return None

            # Check if output is empty
            if not result.stdout or not result.stdout.strip():
                logger.error("KnockKnock produced empty output")
                logger.error(f"STDERR: {result.stderr}")
                return None

            # KnockKnock outputs progress information before JSON
            # Extract the JSON portion (starts with '{')
            stdout = result.stdout
            json_start = stdout.find('{')

            if json_start == -1:
                logger.error("No JSON found in KnockKnock output")
                logger.error(f"First 500 chars of stdout: {stdout[:500]}")
                return None

            # Extract JSON portion
            json_output = stdout[json_start:]

            # Parse JSON output
            try:
                scan_data = json.loads(json_output)

                # Add metadata
                scan_result = {
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "virustotal_enabled": not skip_virustotal,
                    "data": scan_data
                }

                # Count items
                total_items = sum(len(items) for items in scan_data.values() if isinstance(items, list))
                print(f"   ✅ KnockKnock scan complete ({total_items} persistence items found)")

                return scan_result

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse KnockKnock JSON output: {e}")
                logger.error(f"First 500 chars of stdout: {result.stdout[:500]}")
                logger.error(f"STDERR: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("KnockKnock scan timed out after 5 minutes")
            return None
        except Exception as e:
            logger.error(f"Error running KnockKnock scan: {e}")
            return None

    def run_baseline_scan(self) -> bool:
        """
        Run baseline scan before installation.

        Returns:
            True if successful, False otherwise
        """
        print("\n📸 Running KnockKnock baseline scan (this may take a few minutes)...")

        # Check config for VirusTotal integration
        config = get_config()
        use_vt = config.is_knockknock_virustotal_enabled()
        self.baseline_scan = self.run_scan(skip_virustotal=not use_vt)

        if self.baseline_scan:
            logger.info("KnockKnock baseline scan completed successfully")
            return True
        else:
            logger.warning("KnockKnock baseline scan failed")
            return False

    def run_post_install_scan(self) -> bool:
        """
        Run post-installation scan.

        Returns:
            True if successful, False otherwise
        """
        print("\n🔍 Running KnockKnock post-installation scan...")
        print("   (This may take a few minutes)")

        # Check config for VirusTotal integration
        config = get_config()
        use_vt = config.is_knockknock_virustotal_enabled()
        self.post_install_scan = self.run_scan(skip_virustotal=not use_vt)

        if self.post_install_scan:
            logger.info("KnockKnock post-installation scan completed successfully")
            return True
        else:
            logger.warning("KnockKnock post-installation scan failed")
            return False

    def compare_scans(self) -> Dict[str, Any]:
        """
        Compare baseline and post-installation scans.

        KnockKnock v4.0.2+ includes refactored comparison logic (#45)
        for improved accuracy and performance.

        Returns:
            Dict containing comparison results with new/modified items
        """
        if not self.baseline_scan or not self.post_install_scan:
            logger.error("Cannot compare scans - baseline or post-install scan missing")
            return {
                "error": "Incomplete scan data",
                "new_items": [],
                "modified_items": [],
                "removed_items": []
            }

        baseline_data = self.baseline_scan["data"]
        post_install_data = self.post_install_scan["data"]

        new_items = []
        modified_items = []
        removed_items = []

        # Get all categories from both scans
        all_categories = set(baseline_data.keys()) | set(post_install_data.keys())

        for category in all_categories:
            baseline_items = baseline_data.get(category, [])
            post_install_items = post_install_data.get(category, [])

            # Convert to sets of identifiable keys for comparison
            # KnockKnock items typically have 'path' as identifier
            baseline_paths = {self._get_item_identifier(item): item for item in baseline_items}
            post_install_paths = {self._get_item_identifier(item): item for item in post_install_items}

            # Find new items
            new_paths = set(post_install_paths.keys()) - set(baseline_paths.keys())
            for path in new_paths:
                item = post_install_paths[path]
                new_items.append({
                    "category": category,
                    "item": item,
                    "path": path
                })

            # Find removed items
            removed_paths = set(baseline_paths.keys()) - set(post_install_paths.keys())
            for path in removed_paths:
                item = baseline_paths[path]
                removed_items.append({
                    "category": category,
                    "item": item,
                    "path": path
                })

            # Find modified items (same path, different content)
            common_paths = set(baseline_paths.keys()) & set(post_install_paths.keys())
            for path in common_paths:
                baseline_item = baseline_paths[path]
                post_item = post_install_paths[path]

                # Simple comparison - could be enhanced
                if baseline_item != post_item:
                    modified_items.append({
                        "category": category,
                        "path": path,
                        "baseline_item": baseline_item,
                        "post_install_item": post_item
                    })

        comparison = {
            "new_items": new_items,
            "modified_items": modified_items,
            "removed_items": removed_items,
            "new_count": len(new_items),
            "modified_count": len(modified_items),
            "removed_count": len(removed_items)
        }

        logger.info(f"KnockKnock comparison: {len(new_items)} new, {len(modified_items)} modified, {len(removed_items)} removed")

        return comparison

    def _get_item_identifier(self, item: Dict) -> str:
        """
        Extract a unique identifier from a KnockKnock item.

        Args:
            item: KnockKnock item dictionary

        Returns:
            String identifier (typically the path)
        """
        # Try different possible identifier fields
        for key in ['path', 'file', 'bundle', 'script']:
            if key in item:
                return item[key]

        # Fallback to string representation
        return str(item)

    def get_scan_summary(self) -> Dict[str, Any]:
        """
        Get a summary of scan results for reporting.

        Returns:
            Dict containing scan summary information
        """
        summary = {
            "baseline_completed": self.baseline_scan is not None,
            "post_install_completed": self.post_install_scan is not None,
            "comparison_available": self.baseline_scan is not None and self.post_install_scan is not None
        }

        if summary["baseline_completed"]:
            baseline_data = self.baseline_scan["data"]
            summary["baseline_total"] = sum(len(items) for items in baseline_data.values() if isinstance(items, list))
            summary["baseline_categories"] = len(baseline_data)

        if summary["post_install_completed"]:
            post_data = self.post_install_scan["data"]
            summary["post_install_total"] = sum(len(items) for items in post_data.values() if isinstance(items, list))
            summary["post_install_categories"] = len(post_data)

        if summary["comparison_available"]:
            comparison = self.compare_scans()
            summary["changes"] = {
                "new_items": comparison["new_count"],
                "modified_items": comparison["modified_count"],
                "removed_items": comparison["removed_count"]
            }

        return summary
