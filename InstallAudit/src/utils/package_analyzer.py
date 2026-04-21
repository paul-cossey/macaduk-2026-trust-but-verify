# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Package analysis module for checking deprecated dependencies in PKG files.
"""

import subprocess
import os
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class PackageAnalyzer:
    """Analyzes PKG files for deprecated dependencies and other issues."""

    def __init__(self):
        """Initialize the PackageAnalyzer."""
        self.pkgcheck_script = os.path.join(
            os.path.dirname(__file__),
            'pkgcheck.sh'
        )
        self.cache_directory = '/Library/Managed Installs/Cache'

    def analyze_packages_in_cache(self) -> Dict[str, Any]:
        """
        Analyze all packages in the Munki cache directory.

        Returns:
            Dict containing package analysis results
        """
        try:
            print("\n📦 Analyzing packages for deprecated dependencies...")

            if not os.path.exists(self.cache_directory):
                print(f"❌ Cache directory not found: {self.cache_directory}")
                return {"error": "Cache directory not found"}

            # Find all packages in cache
            packages_found = []
            dmgs_found = []

            for item in os.listdir(self.cache_directory):
                item_path = os.path.join(self.cache_directory, item)
                if os.path.isfile(item_path):
                    if item.lower().endswith(('.pkg', '.mpkg')):
                        packages_found.append(item_path)
                    elif item.lower().endswith('.dmg'):
                        dmgs_found.append(item_path)

            if not packages_found and not dmgs_found:
                print("ℹ️  No PKG or DMG files found in cache directory")
                return {"packages_found": 0, "analysis_results": []}

            print(f"📦 Found {len(packages_found)} PKG file(s) and {len(dmgs_found)} DMG file(s)")

            analysis_results = []

            # Analyze PKG files directly
            for pkg_path in packages_found:
                print(f"🔍 Analyzing {os.path.basename(pkg_path)}...")
                result = self._analyze_single_package(pkg_path)
                if result:
                    analysis_results.append(result)

            # Analyze DMG files (which may contain PKGs)
            for dmg_path in dmgs_found:
                print(f"🔍 Analyzing {os.path.basename(dmg_path)}...")
                result = self._analyze_single_package(dmg_path)
                if result:
                    analysis_results.append(result)

            # Summary
            total_issues = sum(len(result.get('deprecated_dependencies', [])) for result in analysis_results)
            critical_issues = sum(len(result.get('critical_issues', [])) for result in analysis_results)

            if total_issues > 0:
                print(f"⚠️  Found {total_issues} deprecated dependency issue(s)")
                if critical_issues > 0:
                    print(f"🚨 Found {critical_issues} critical issue(s) (Python 2 usage)")
            else:
                print("✅ No deprecated dependencies found")

            return {
                "packages_found": len(packages_found) + len(dmgs_found),
                "analysis_results": analysis_results,
                "total_issues": total_issues,
                "critical_issues": critical_issues
            }

        except Exception as e:
            logger.error(f"Error analyzing packages: {e}")
            print(f"❌ Error analyzing packages: {e}")
            return {"error": str(e)}

    def analyze_single_package(self, package_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a single package file (public method for external use).

        Args:
            package_path: Path to the package file (.pkg, .mpkg, or .dmg)

        Returns:
            Dict containing analysis results or None if analysis fails
        """
        try:
            if not os.path.exists(package_path):
                print(f"❌ Package file not found: {package_path}")
                return {"error": "Package file not found"}

            print(f"🔍 Analyzing {os.path.basename(package_path)}...")
            result = self._analyze_single_package(package_path)

            if result:
                # Show summary
                if result.get("deprecated_dependencies"):
                    issues = len(result["deprecated_dependencies"])
                    print(f"   ⚠️  Found {issues} deprecated dependency issue(s)")
                    if result.get("critical"):
                        print("   🚨 Critical issues found")
                else:
                    print("   ✅ No deprecated dependencies found")

            return result

        except Exception as e:
            logger.error(f"Error analyzing package: {e}")
            print(f"❌ Error analyzing package: {e}")
            return {"error": str(e)}

    def _analyze_single_package(self, package_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze a single package file using the pkgcheck script.

        Args:
            package_path: Path to the package file

        Returns:
            Dict containing analysis results or None if analysis fails
        """
        try:
            # Run pkgcheck script
            result = subprocess.run(
                [self.pkgcheck_script, package_path],
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )

            if result.returncode != 0:
                print(f"   ⚠️  pkgcheck returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    print(f"   Error: {result.stderr}")
                return None

            # Parse the structured output
            analysis_result = self._parse_pkgcheck_output(result.stdout, package_path)

            return analysis_result

        except subprocess.TimeoutExpired:
            print(f"   ❌ Analysis timed out for {os.path.basename(package_path)}")
            return None
        except Exception as e:
            logger.error(f"Error analyzing {package_path}: {e}")
            print(f"   ❌ Error analyzing {os.path.basename(package_path)}: {e}")
            return None

    def _parse_pkgcheck_output(self, output: str, package_path: str) -> Dict[str, Any]:
        """
        Parse the structured output from pkgcheck script.

        Args:
            output: Raw output from pkgcheck script
            package_path: Path to the analyzed package

        Returns:
            Dict containing parsed analysis results
        """
        result = {
            "package_path": package_path,
            "package_name": os.path.basename(package_path),
            "package_info": {},
            "components": [],
            "deprecated_dependencies": [],
            "critical_issues": [],
            "python_usage": [],
            "signature": None,
            "notarized": None,
            "dmg_info": {},
            "errors": []
        }

        current_component = None

        for line in output.strip().split('\n'):
            if ':' not in line:
                continue

            # Main package information
            if line.startswith('PKG_NAME:'):
                result["package_info"]["name"] = line.split(':', 1)[1]
            elif line.startswith('PKG_TYPE:'):
                result["package_info"]["type"] = line.split(':', 1)[1]
            elif line.startswith('PKG_IDENTIFIER:'):
                result["package_info"]["identifier"] = line.split(':', 1)[1]
            elif line.startswith('PKG_VERSION:'):
                result["package_info"]["version"] = line.split(':', 1)[1]
            elif line.startswith('PKG_LOCATION:'):
                result["package_info"]["install_location"] = line.split(':', 1)[1]
            elif line.startswith('PKG_SIGNATURE:'):
                result["signature"] = line.split(':', 1)[1]
            elif line.startswith('PKG_NOTARIZED:'):
                result["notarized"] = line.split(':', 1)[1]
            elif line.startswith('PKG_COMPONENTS:'):
                result["package_info"]["components_count"] = line.split(':', 1)[1]

            # Component information (indented lines)
            elif line.startswith('    PKG_INFO:'):
                # New component
                current_component = {
                    "name": line.split(':', 1)[1],
                    "info": {},
                    "status": "enabled"  # default
                }
                result["components"].append(current_component)
            elif line.startswith('    PKG_TYPE:') and current_component:
                current_component["info"]["type"] = line.split(':', 1)[1]
            elif line.startswith('    PKG_IDENTIFIER:') and current_component:
                current_component["info"]["identifier"] = line.split(':', 1)[1]
            elif line.startswith('    PKG_VERSION:') and current_component:
                current_component["info"]["version"] = line.split(':', 1)[1]
            elif line.startswith('    PKG_LOCATION:') and current_component:
                current_component["info"]["install_location"] = line.split(':', 1)[1]
            elif line.startswith('    PKG_STATUS:') and current_component:
                current_component["status"] = line.split(':', 1)[1]

            # DMG information
            elif line.startswith('DMG_INFO:'):
                result["dmg_info"]["name"] = line.split(':', 1)[1]
            elif line.startswith('DMG_MOUNTED:'):
                result["dmg_info"]["mounted_path"] = line.split(':', 1)[1]
            elif line.startswith('DMG_UNMOUNTED:'):
                result["dmg_info"]["unmounted"] = True

            # Script analysis
            elif line.startswith('DEPRECATED_SHEBANG:'):
                # Format: DEPRECATED_SHEBANG:script_path:shebang
                parts = line.split(':', 2)
                if len(parts) == 3:
                    script_path, shebang = parts[1], parts[2]
                    result["deprecated_dependencies"].append({
                        "type": "deprecated_shebang",
                        "script": script_path,
                        "shebang": shebang,
                        "severity": "warning"
                    })
            elif line.startswith('    DEPRECATED_SHEBANG:'):
                # Component-level deprecated shebang
                parts = line.split(':', 2)
                if len(parts) == 3:
                    script_path, shebang = parts[1], parts[2]
                    result["deprecated_dependencies"].append({
                        "type": "deprecated_shebang",
                        "script": script_path.strip(),
                        "shebang": shebang,
                        "severity": "warning",
                        "component": current_component["name"] if current_component else "unknown"
                    })
            elif line.startswith('CRITICAL_DEPRECATED_SHEBANG:'):
                # Format: CRITICAL_DEPRECATED_SHEBANG:script_path:shebang
                parts = line.split(':', 2)
                if len(parts) == 3:
                    script_path, shebang = parts[1], parts[2]
                    result["critical_issues"].append({
                        "type": "critical_deprecated_shebang",
                        "script": script_path,
                        "shebang": shebang,
                        "severity": "critical",
                        "description": "Python 2 usage - will break in macOS 12.3+"
                    })
            elif line.startswith('    CRITICAL_DEPRECATED_SHEBANG:'):
                # Component-level critical deprecated shebang
                parts = line.split(':', 2)
                if len(parts) == 3:
                    script_path, shebang = parts[1], parts[2]
                    result["critical_issues"].append({
                        "type": "critical_deprecated_shebang",
                        "script": script_path.strip(),
                        "shebang": shebang,
                        "severity": "critical",
                        "description": "Python 2 usage - will break in macOS 12.3+",
                        "component": current_component["name"] if current_component else "unknown"
                    })
            elif line.startswith('PYTHON_USAGE:'):
                # Format: PYTHON_USAGE:script_path
                script_path = line.split(':', 1)[1]
                result["python_usage"].append({
                    "script": script_path,
                    "type": "python_reference"
                })
            elif line.startswith('    PYTHON_USAGE:'):
                # Component-level python usage
                script_path = line.split(':', 1)[1].strip()
                result["python_usage"].append({
                    "script": script_path,
                    "type": "python_reference",
                    "component": current_component["name"] if current_component else "unknown"
                })
            elif line.startswith('ERROR:'):
                error_msg = line.split(':', 1)[1]
                result["errors"].append(error_msg)

        return result

    def get_analysis_summary(self, analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of all package analysis results.

        Args:
            analysis_results: List of individual package analysis results

        Returns:
            Dict containing summary information
        """
        if not analysis_results:
            return {
                "total_packages": 0,
                "packages_with_issues": 0,
                "total_deprecated_dependencies": 0,
                "total_critical_issues": 0,
                "issue_breakdown": {}
            }

        total_packages = len(analysis_results)
        packages_with_issues = 0
        total_deprecated = 0
        total_critical = 0
        issue_breakdown = {}

        for result in analysis_results:
            deprecated_count = len(result.get('deprecated_dependencies', []))
            critical_count = len(result.get('critical_issues', []))

            if deprecated_count > 0 or critical_count > 0:
                packages_with_issues += 1

            total_deprecated += deprecated_count
            total_critical += critical_count

            # Count issue types
            for issue in result.get('deprecated_dependencies', []):
                issue_type = issue.get('type', 'unknown')
                issue_breakdown[issue_type] = issue_breakdown.get(issue_type, 0) + 1

            for issue in result.get('critical_issues', []):
                issue_type = issue.get('type', 'unknown')
                issue_breakdown[issue_type] = issue_breakdown.get(issue_type, 0) + 1

        return {
            "total_packages": total_packages,
            "packages_with_issues": packages_with_issues,
            "total_deprecated_dependencies": total_deprecated,
            "total_critical_issues": total_critical,
            "issue_breakdown": issue_breakdown
        }
