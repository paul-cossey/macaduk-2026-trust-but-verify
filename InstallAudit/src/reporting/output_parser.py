# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Output parser module for handling process output and data formatting.
"""

import re
import logging

# Set up logging
logger = logging.getLogger(__name__)


class OutputParser:
    """Handles parsing and formatting of process output and data."""

    def __init__(self):
        """Initialize the OutputParser."""
        pass

    def _handle_process_output(self, process, _action_type=""):
        """Handle process output with reduced noise"""
        output_lines = []
        last_significant_line = None
        progress_pattern = re.compile(r'^[\s→]*([0-9.]+)(?:\s*percent complete)?$')
        last_percentage = -1

        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                line = output.strip()

                # Skip empty lines
                if not line:
                    continue

                # Check if this is a progress indicator line
                progress_match = progress_pattern.match(line)
                if progress_match:
                    try:
                        # Try to extract percentage
                        current = float(progress_match.group(1).rstrip('.'))
                        # Only show 0, 25, 50, 75, and 100 percent
                        if current in [0, 25, 50, 75, 100] and current > last_percentage:
                            print(f"   → {int(current)}% complete")
                            output_lines.append(f"   → {int(current)}% complete")
                            last_percentage = current
                    except ValueError:
                        continue
                    continue

                # Skip redundant progress lines
                if any(x in line for x in ['Downloading', 'Copying', 'Installing']):
                    if line != last_significant_line:
                        print(f"   → {line}")
                        output_lines.append(f"   → {line}")
                        last_significant_line = line
                    continue

                # Include all other lines
                # Skip lines that are just numbers, dots, and arrows
                if not line.strip('→ .0123456789'):
                    continue

                print(f"   → {line}")
                output_lines.append(f"   → {line}")

        return output_lines

    def _process_dhs_data(self, event):
        """Process DHS scan data and return formatted findings"""
        try:
            dhs_output = event.get('event', '')
            if not dhs_output:
                return "No DHS findings detected"

            # Try to parse as JSON first (new DHS format)
            try:
                import json
                dhs_data = json.loads(dhs_output)

                # Extract vulnerable files for VirusTotal analysis
                vulnerable_files = []
                hijacked_apps = dhs_data.get("hijacked applications", [])
                vulnerable_apps = dhs_data.get("vulnerable applications", [])

                # Store vulnerable file paths for potential VirusTotal analysis
                for app in hijacked_apps:
                    if self.BINARY_PATH_KEY in app:
                        vulnerable_files.append(app[self.BINARY_PATH_KEY])

                for app in vulnerable_apps:
                    if self.BINARY_PATH_KEY in app:
                        vulnerable_files.append(app[self.BINARY_PATH_KEY])

                # Store the vulnerable files list in the event for later VirusTotal analysis
                if hasattr(self, 'dhs_vulnerable_files'):
                    self.dhs_vulnerable_files.extend(vulnerable_files)
                else:
                    self.dhs_vulnerable_files = vulnerable_files

                # Format findings for display
                findings = []

                if hijacked_apps:
                    findings.append("**Hijacked Applications:**")
                    for app in hijacked_apps:
                        findings.append(f"- Binary: {app.get(self.BINARY_PATH_KEY, 'Unknown')}")
                        if 'issue' in app:
                            findings.append(f"  Issue: {app['issue']}")
                        if 'dylib path' in app:
                            findings.append(f"  Dylib: {app['dylib path']}")
                        findings.append("")

                if vulnerable_apps:
                    findings.append("**Vulnerable Applications:**")
                    for app in vulnerable_apps:
                        findings.append(f"- Binary: {app.get(self.BINARY_PATH_KEY, 'Unknown')}")
                        if 'issue' in app:
                            findings.append(f"  Issue: {app['issue']}")
                        if 'dylib path' in app:
                            findings.append(f"  Dylib: {app['dylib path']}")
                        findings.append("")

                if findings:
                    return "\n".join(findings)
                else:
                    return "No security issues detected by DHS"

            except json.JSONDecodeError:
                # Fall back to text processing for older DHS format
                pass

            # Original text processing logic (fallback for older DHS format)
            lines = dhs_output.splitlines()
            findings = []
            current_finding = None

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Check for finding headers (typically start with indicators)
                if any(indicator in line.lower() for indicator in ['suspicious', 'malware', 'threat', 'warning', 'alert']):
                    if current_finding:
                        findings.append(current_finding)
                    current_finding = [line]
                elif current_finding:
                    current_finding.append(f"  {line}")

            # Add the last finding
            if current_finding:
                findings.append(current_finding)

            if findings:
                result = []
                for finding in findings:
                    result.extend(finding)
                    result.append("")  # Add spacing between findings
                return "\n".join(result)
            else:
                return "No security issues detected by DHS"

        except Exception as e:
            logger.error(f"Error processing DHS data: {e}")
            return f"Error processing DHS data: {str(e)}"
