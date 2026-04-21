# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Report generator module for creating markdown reports.
"""

import os
import re
import logging

# Set up logging
logger = logging.getLogger(__name__)


class ReportGenerator:
    """Handles generation of markdown reports for testing results."""

    # Constants for duplicated string literals
    UNKNOWN_APPLICATION = "Unknown application"
    NO_SYSTEM_EXTENSIONS = "No System Extensions found"
    NO_LOGIN_ITEMS_CHANGES = "No login items changes detected"
    INDENTED_CODE_BLOCK = "    ```"

    def __init__(self):
        """Initialize the ReportGenerator."""
        # These attributes will be available through multiple inheritance
        # in the CompositeTester class from AutoUpdateTester
        pass

    def _format_vt_file_status(self, result):
        """Format status section for a VirusTotal file result.

        Args:
            result: Dictionary containing file scan results

        Returns:
            list: Formatted status lines
        """
        lines = []
        status = result.get("status", "unknown")

        if status == "clean":
            scan_results = result.get("scan_results", {})
            ratio = scan_results.get("detection_ratio", "0/0")
            lines.append(f"  Status: ✅ CLEAN ({ratio} detections)")
        elif status == "malicious":
            scan_results = result.get("scan_results", {})
            ratio = scan_results.get("detection_ratio", "unknown")
            lines.append(f"  Status: 🚨 MALICIOUS ({ratio} detections)")
        elif status == "suspicious":
            scan_results = result.get("scan_results", {})
            ratio = scan_results.get("detection_ratio", "unknown")
            lines.append(f"  Status: ⚠️ SUSPICIOUS ({ratio} detections)")
        elif status == "too_large":
            lines.append("  Status: 📦 TOO LARGE FOR ANALYSIS")
            lines.append("  Action required: Manual VirusTotal verification needed")
        elif status == "not_found":
            lines.append("  Status: ❓ NOT FOUND IN DATABASE")
            lines.append("  Action required: Manual verification recommended")
        elif status == "error":
            error_msg = result.get("message", "Unknown error")
            lines.append("  Status: ❌ ANALYSIS FAILED")
            lines.append(f"  Error: {error_msg}")

        return lines

    def _add_vt_file_metadata(self, result):
        """Add metadata fields for a VirusTotal file result.

        Args:
            result: Dictionary containing file scan results

        Returns:
            list: Formatted metadata lines
        """
        lines = []

        if result.get("permalink"):
            lines.append(f"  Report URL: {result['permalink']}")

        if result.get("analysis_type"):
            lines.append(f"  Analysis type: {result['analysis_type']}")

        if result.get("download_url"):
            lines.append(f"  Analyzed URL: {result['download_url']}")

        if result.get("sha256"):
            lines.append(f"  SHA-256: {result['sha256']}")

        return lines

    def _add_vt_summary_recommendation(self, malicious_files, suspicious_files, error_files, manual_check):
        """Add summary and recommendation for VirusTotal analysis.

        Args:
            malicious_files: Count of malicious files
            suspicious_files: Count of suspicious files
            error_files: Count of files with errors
            manual_check: Count of files requiring manual check

        Returns:
            list: Formatted recommendation lines
        """
        if malicious_files > 0:
            return [
                "🚨 SECURITY ALERT: Malicious files detected!",
                "Action required: Do not deploy this software until malware is resolved.",
                ""
            ]
        elif suspicious_files > 0:
            return [
                "⚠️ WARNING: Suspicious files detected.",
                "Action required: Review VirusTotal reports before deployment.",
                ""
            ]
        elif error_files > 0:
            return [
                "❌ ANALYSIS ERRORS: Some files could not be analyzed.",
                "Action required: Manual VirusTotal verification required for failed analyses.",
                ""
            ]
        elif manual_check > 0:
            return [
                "📋 Manual verification required for some files.",
                "Action required: Upload large files manually to VirusTotal.",
                ""
            ]
        else:
            return [
                "✅ All analyzed files passed malware screening.",
                ""
            ]

    def _format_virustotal_section(self):
        """Format VirusTotal malware analysis section.

        Returns:
            list: Lines to add to the report sections
        """
        sections = [
            "",
            "### VirusTotal Malware Analysis",
            ""
        ]

        if "virustotal_analysis" not in self.report_data:
            sections.extend([
                "```",
                "VirusTotal analysis was not performed.",
                "```"
            ])
            return sections

        vt_data = self.report_data["virustotal_analysis"]

        if "error" in vt_data:
            sections.extend([
                "```",
                f"VirusTotal analysis failed: {vt_data['error']}",
                "Manual malware verification recommended.",
                "```"
            ])
            return sections

        # Extract summary stats
        total_files = vt_data.get("total_files", 0)
        clean_files = vt_data.get("clean_files", 0)
        malicious_files = vt_data.get("malicious_files", 0)
        suspicious_files = vt_data.get("suspicious_files", 0)
        manual_check = vt_data.get("manual_check_required", 0)

        # Count files with analysis errors
        error_files = 0
        if vt_data.get("results"):
            error_files = len([r for r in vt_data["results"] if r.get("status") == "error"])

        sections.extend([
            "```",
            f"Files analyzed: {total_files}",
            f"Clean files: {clean_files}",
            f"Malicious files: {malicious_files}",
            f"Suspicious files: {suspicious_files}",
            f"Manual check required: {manual_check}",
            f"Analysis errors: {error_files}",
            ""
        ])

        # Format detailed results
        if vt_data.get("results"):
            sections.append("Detailed analysis results:")
            sections.append("")

            for result in vt_data["results"]:
                file_name = result.get("file_name", "Unknown")
                file_size = result.get("file_size_mb", "unknown")

                sections.append(f"File: {file_name} ({file_size} MB)")
                sections.extend(self._format_vt_file_status(result))
                sections.extend(self._add_vt_file_metadata(result))
                sections.append("")

        # Add summary and recommendations
        sections.extend(self._add_vt_summary_recommendation(
            malicious_files, suspicious_files, error_files, manual_check
        ))

        sections.append("```")
        return sections

    def _format_tl_binary_basic_info(self, result):
        """Format basic information for a ThreatLabs binary result.

        Args:
            result: Dictionary containing binary analysis results

        Returns:
            list: Formatted basic info lines
        """
        lines = []
        lines.append(f"Binary: {result.get('name', 'Unknown')}")
        lines.append(f"  Source: {result.get('source_app', 'Unknown')}")

        # Add app bundle if it's different from source and not None
        app_bundle = result.get('app_bundle')
        source_app = result.get('source_app', 'Unknown')
        logger.debug(f"Binary {result.get('name')}: app_bundle={app_bundle}, source_app={source_app}")
        if app_bundle and app_bundle != source_app:
            lines.append(f"  App Bundle: {app_bundle}")

        lines.append(f"  Path: {result.get('path', 'Unknown')}")
        lines.append(f"  SHA-256: {result.get('sha256', 'Unknown')}")

        # Add developer/signing info if available
        if result.get('developer_name'):
            lines.append(f"  Developer: {result['developer_name']}")
        if result.get('signing_id'):
            lines.append(f"  Signing ID: {result['signing_id']}")

        # Add submission ID if available
        if result.get('submission_id'):
            lines.append(f"  Submission ID: {result['submission_id']}")

        return lines

    def _format_tl_threat_level(self, result):
        """Format threat level section for a ThreatLabs binary result.

        Args:
            result: Dictionary containing binary analysis results

        Returns:
            list: Formatted threat level lines
        """
        lines = []
        threat_level = result.get('threat_level', 'unknown').upper()
        status = result.get('status', 'unknown')

        # Special handling for blocked/threat name
        if result.get('blocked'):
            lines.append(f"  🚫 BLOCKED: {result.get('threat_name', 'Unknown threat')}")
            if result.get('blocking_reason'):
                lines.append(f"  Blocking Reason: {result['blocking_reason']}")
        elif result.get('threat_name'):
            lines.append(f"  ⚠️  Threat: {result['threat_name']}")

        # Special handling for too_large files
        if status == 'too_large':
            file_size = result.get('file_size_mb', 'Unknown')
            message = result.get('message', 'File too large')
            lines.append(f"  Status: 📦 TOO LARGE ({file_size} MB)")
            lines.append(f"  Message: {message}")
        elif status == 'unsupported_format' or threat_level == 'UNSUPPORTED':
            file_type = result.get('file_type', 'Unknown')
            message = result.get('message', 'File type not supported by ThreatLabs API')
            lines.append("  Status: 🔧 UNSUPPORTED FORMAT")
            lines.append(f"  File Type: {file_type}")
            lines.append(f"  Message: {message}")
        elif threat_level in ['CLEAN', 'SAFE', 'BENIGN']:
            lines.append(f"  Threat Level: ✅ {threat_level}")
        elif threat_level in ['SUSPICIOUS', 'WARNING']:
            lines.append(f"  Threat Level: ⚠️  {threat_level}")
        elif threat_level in ['MALICIOUS', 'DANGER', 'THREAT']:
            lines.append(f"  Threat Level: 🚨 {threat_level}")
        elif threat_level == 'PENDING':
            lines.append("  Status: ⏳ Analysis Pending")
        else:
            lines.append(f"  Threat Level: ❓ {threat_level}")

        return lines

    def _format_tl_detections(self, result):
        """Format detections section for a ThreatLabs binary result.

        Args:
            result: Dictionary containing binary analysis results

        Returns:
            list: Formatted detection lines
        """
        lines = []

        if result.get('detections'):
            lines.append(f"  Detections: {len(result['detections'])}")
            for detection in result['detections'][:3]:  # Show first 3
                det_type = detection.get('type', 'unknown')
                severity = detection.get('severity', 'unknown')
                desc = detection.get('description', 'No description')
                lines.append(f"    - [{severity.upper()}] {det_type}: {desc}")

            if len(result['detections']) > 3:
                lines.append(f"    ... and {len(result['detections']) - 3} more")

        return lines

    def _add_tl_summary_recommendation(self, summary, results):
        """Add summary and recommendation for ThreatLabs analysis.

        Args:
            summary: Summary statistics dictionary
            results: Full results dictionary

        Returns:
            list: Formatted recommendation lines
        """
        lines = []

        if summary.get('malicious', 0) > 0:
            lines.extend([
                "🚨 SECURITY ALERT: Malicious binaries detected!",
                "Action required: Do not deploy this software until threats are resolved.",
                ""
            ])
        elif summary.get('suspicious', 0) > 0:
            lines.extend([
                "⚠️  WARNING: Suspicious binaries detected.",
                "Action required: Review ThreatLabs reports before deployment.",
                ""
            ])
        elif summary.get('pending', 0) > 0:
            lines.extend([
                "⏳ Some analyses are still pending.",
                "Action required: Check ThreatLabs portal for complete results.",
                ""
            ])
        elif summary.get('clean', 0) > 0:
            lines.extend([
                "✅ All analyzed binaries passed security screening.",
                ""
            ])

        # Add errors if any
        if results.get('errors'):
            lines.append("Errors encountered:")
            for error in results['errors'][:5]:  # Show first 5 errors
                lines.append(f"  - {error}")
            if len(results['errors']) > 5:
                lines.append(f"  ... and {len(results['errors']) - 5} more errors")
            lines.append("")

        return lines

    def _format_threatlabs_section(self):
        """Format ThreatLabs binary analysis section.

        Returns:
            list: Lines to add to the report sections
        """
        if "threatlabs_analysis" not in self.report_data:
            return []

        sections = [
            "",
            "### ThreatLabs Binary Analysis",
            ""
        ]

        tl_data = self.report_data["threatlabs_analysis"]
        summary = tl_data.get("summary", {})
        results = tl_data.get("results", {})

        sections.extend([
            "```",
            f"Total binaries extracted: {summary.get('total_binaries', 0)}",
            f"Binaries submitted: {summary.get('submitted', 0)}",
            f"Binaries skipped: {summary.get('skipped', 0)}",
            "",
            "Analysis Results:",
            f"  Clean: {summary.get('clean', 0)}",
            f"  Suspicious: {summary.get('suspicious', 0)}",
            f"  Malicious: {summary.get('malicious', 0)}",
            f"  Pending: {summary.get('pending', 0)}",
            f"  Unknown: {summary.get('unknown', 0)}",
            f"  Too Large: {summary.get('too_large', 0)}",
            f"  Unsupported Format: {summary.get('unsupported', 0)}",
            ""
        ])

        # Display detailed results (excluding unsupported binaries)
        if results.get('results'):
            # Filter out unsupported binaries for detailed display
            displayable_results = [r for r in results['results'] if r.get('status') != 'unsupported_format']

            if displayable_results:
                sections.append("Detailed Binary Analysis:")
                sections.append("")

                for result in displayable_results:
                    sections.extend(self._format_tl_binary_basic_info(result))
                    sections.extend(self._format_tl_threat_level(result))
                    sections.extend(self._format_tl_detections(result))
                    sections.append("")

        # Summary and recommendations
        sections.extend(self._add_tl_summary_recommendation(summary, results))

        sections.append("```")
        return sections

    def _format_security_tool_sections(self, tool_events):
        """Format all security monitoring tool sections.

        Args:
            tool_events: Dictionary of security events by tool name

        Returns:
            list: Lines to add to the report sections
        """
        sections = []

        # BlockBlock
        sections.extend(self._format_blockblock_section(tool_events))

        # DHS
        sections.extend(self._format_dhs_section(tool_events))

        # LuLu
        sections.extend(self._format_lulu_section(tool_events))

        # XProtect
        sections.extend(self._format_xprotect_section(tool_events))

        # RansomWhere
        sections.extend(self._format_ransomwhere_section(tool_events))

        # OverSight
        sections.extend(self._format_oversight_section(tool_events))

        # ReiKey
        sections.extend(self._format_reikey_section(tool_events))

        return sections

    def _format_bb_binary_info(self, binary_name, binary_path):
        """Format binary information for BlockBlock event.

        Args:
            binary_name: Name of the binary
            binary_path: Path to the binary

        Returns:
            list: Formatted binary info lines
        """
        lines = []
        if binary_name:
            lines.append("  - Binary Information:")
            lines.append(f"    • Name: {binary_name}")
            if binary_path:
                lines.append(f"    • Path: {binary_path}")
        return lines

    def _format_bb_launch_service(self, path):
        """Format launch service details for BlockBlock event.

        Args:
            path: Path to the launch service

        Returns:
            list: Formatted launch service lines
        """
        lines = []
        if "LaunchDaemons" in path:
            lines.append("  - Launch Service Details:")
            lines.append("    • Type: Daemon")
        elif "LaunchAgents" in path:
            lines.append("  - Launch Service Details:")
            lines.append("    • Type: Agent")
        return lines

    def _format_bb_process_info(self, process_info):
        """Format process information for BlockBlock event.

        Args:
            process_info: Dictionary containing process information

        Returns:
            list: Formatted process info lines
        """
        lines = []
        if process_info and any(process_info.values()):
            lines.append("  - Process Information:")
            if process_info.get('name'):
                lines.append(f"    • Name: {process_info.get('name')}")
            if process_info.get('pid'):
                lines.append(f"    • PID: {process_info.get('pid')}")
            if process_info.get('path'):
                lines.append(f"    • Path: {process_info.get('path')}")
            if process_info.get('architecture'):
                lines.append(f"    • Architecture: {process_info.get('architecture')}")
            if process_info.get('uid'):
                lines.append(f"    • UID: {process_info.get('uid')}")

            signing = process_info.get('signing info (reported)', {})
            if signing:
                lines.append("    • Signing Information:")
                lines.append(f"      - Signing ID: {signing.get('signingID', '')}")
                lines.append(f"      - Team ID: {signing.get('teamID', '')}")
                lines.append(f"      - Platform Binary: {signing.get('platformBinary', '')}")
                lines.append(f"      - CS Flags: {signing.get('csFlags', '')}")
                if signing.get('cdHash'):
                    lines.append(f"      - CD Hash: {signing.get('cdHash')}")
        return lines

    def _format_blockblock_section(self, tool_events):
        """Format BlockBlock events section."""
        sections = [
            "",
            "### BLOCKBLOCK",
            "#### Installation Phase Events:",
            "```"
        ]

        if "BLOCKBLOCK" in tool_events:
            seen_events = set()
            persistence_events = []
            paste_protection_events = []

            for event in tool_events["BLOCKBLOCK"]:
                if isinstance(event.get('event'), dict):
                    event_type = event['event'].get('type', 'user_action')

                    # Handle paste protection events (v2.3.0+)
                    if event_type == 'paste_protection':
                        paste_event_entry = self._format_paste_protection_event(event)
                        if paste_event_entry:
                            paste_protection_events.extend(paste_event_entry)
                            paste_protection_events.append("")
                        continue

                    # Handle regular persistence events
                    details = event['event'].get('details', {})
                    timestamp = event.get('timestamp', 'Unknown')
                    path = details.get('path', '')
                    binary_name = details.get('binary_name', '')
                    binary_path = details.get('binary_path', '')
                    action = details.get('action', '')
                    event_time = details.get('timestamp', '')
                    process_info = details.get('process', {})

                    if not path or path == "Unknown":
                        path = self.UNKNOWN_APPLICATION

                    key = (path, binary_name)
                    if key in seen_events:
                        continue
                    seen_events.add(key)

                    event_entry = [f"- [{timestamp}] BlockBlock allowed: {os.path.basename(path)}"]
                    event_entry.append(f"  - Path: {path}")
                    event_entry.extend(self._format_bb_binary_info(binary_name, binary_path))
                    event_entry.extend(self._format_bb_launch_service(path))
                    event_entry.extend(self._format_bb_process_info(process_info))

                    if action:
                        event_entry.append(f"  - Action: {action}")
                    if event_time and event_time != timestamp:
                        event_entry.append(f"  - Event Time: {event_time}")

                    persistence_events.extend(event_entry)
                    persistence_events.append("")

            # Add persistence events
            if persistence_events:
                sections.extend(persistence_events)
            else:
                sections.append("No persistence events detected")

            # Add paste protection events if any
            if paste_protection_events:
                sections.append("")
                sections.append("#### Paste Protection Events (v2.3.0+):")
                sections.extend(paste_protection_events)
        else:
            sections.append("No BlockBlock events detected")

        sections.append("```")
        return sections

    def _format_paste_protection_event(self, event):
        """Format a BlockBlock paste protection event.

        Args:
            event: Paste protection event dict

        Returns:
            List of formatted strings
        """
        details = event['event'].get('details', {})
        timestamp = event.get('timestamp', 'Unknown')
        target_app = details.get('target_app', 'Unknown')
        action = details.get('action', 'alerted')
        paste_preview = details.get('paste_preview', '')
        process = details.get('process', {})

        event_entry = [f"- [{timestamp}] Paste Protection Alert: {target_app}"]
        event_entry.append(f"  - Action: {action}")
        event_entry.append(f"  - Target Application: {target_app}")

        if paste_preview:
            # Sanitize and truncate preview
            safe_preview = paste_preview.replace('\n', ' ').replace('\r', ' ')[:100]
            event_entry.append(f"  - Paste Content Preview: {safe_preview}...")

        if process and process.get('name'):
            event_entry.append(f"  - Source Process: {process['name']}")

        event_entry.append("  - ⚠️  Potential ClickFix attack attempt detected")

        return event_entry

    def _format_dhs_section(self, tool_events):
        """Format DHS events section."""
        sections = [
            "",
            "### DHS",
            "```"
        ]

        if "DHS" in tool_events:
            dhs_findings = []
            for event in tool_events["DHS"]:
                processed_dhs = self._process_dhs_data(event)
                if processed_dhs and processed_dhs != "No DHS findings detected":
                    dhs_findings.append(processed_dhs)

            if dhs_findings:
                sections.extend(dhs_findings)
            else:
                sections.append("No security issues detected by DHS")
        else:
            sections.append("No DHS scan results available")
        sections.append("```")

        # DHS VirusTotal Analysis
        dhs_vt_events = [event for event in self.report_data.get("security_events", [])
                         if event.get("tool") == "VirusTotal-DHS"]

        if dhs_vt_events:
            sections.extend([
                "",
                "### DHS VirusTotal Analysis",
                "```"
            ])

            for event in dhs_vt_events:
                details = event.get("details", {})
                file_path = details.get("file_path", "unknown")
                filename = os.path.basename(file_path) if file_path != "unknown" else "unknown"
                status = details.get("status", "unknown")

                if status == "clean":
                    detections = details.get("scan_results", {}).get("detection_ratio", "0/0")
                    sections.append(f"File: {filename}")
                    sections.append(f"  Status: ✅ CLEAN ({detections} detections)")
                    if details.get("permalink"):
                        sections.append(f"  Report URL: {details['permalink']}")
                elif status == "malicious":
                    detections = details.get("scan_results", {}).get("detection_ratio", "unknown")
                    sections.append(f"File: {filename}")
                    sections.append(f"  Status: ⚠️ MALICIOUS ({detections} detections)")
                    if details.get("permalink"):
                        sections.append(f"  Report URL: {details['permalink']}")
                elif status == "suspicious":
                    detections = details.get("scan_results", {}).get("detection_ratio", "unknown")
                    sections.append(f"File: {filename}")
                    sections.append(f"  Status: ⚠️ SUSPICIOUS ({detections} detections)")
                    if details.get("permalink"):
                        sections.append(f"  Report URL: {details['permalink']}")
                else:
                    sections.append(f"File: {filename}")
                    sections.append(f"  Status: {status}")
                    if details.get("error"):
                        sections.append(f"  Error: {details['error']}")

                sections.append("")

            sections.append("```")

        return sections

    def _format_lulu_section(self, tool_events):
        """Format LuLu network events section.

        LuLu v4.2.1+ Features:
        - Relative rule durations instead of fixed end times (#811, #813)
        - User-created rules can be exported/imported (#814)
        - Flows for exited processes now denied (security improvement)
        - UI improvements for better user experience (#812)

        Report format remains compatible across all LuLu versions.
        """
        sections = [
            "",
            "### LULU",
            "```"
        ]

        if "LULU" in tool_events and tool_events["LULU"]:
            lulu_events = []
            seen_events = set()

            for event in tool_events["LULU"]:
                if event.get('event') and isinstance(event['event'], dict):
                    details = event['event']['details']
                    timestamp = event.get('timestamp', 'Unknown')
                    app_path = details.get('app_path', '')
                    action = details.get('action', 'unknown')
                    connection = details.get('connection', '')

                    key = (app_path, connection)
                    if key in seen_events:
                        continue
                    seen_events.add(key)

                    app_name = os.path.basename(app_path) if app_path else self.UNKNOWN_APPLICATION
                    event_entry = [f"- [{timestamp}] LuLu {action}: {app_name}"]
                    if app_path:
                        event_entry.append(f"  - Application Path: {app_path}")
                    if connection:
                        event_entry.append(f"  - Network Connection: {connection}")

                    lulu_events.extend(event_entry)
                    lulu_events.append("")

                elif event.get('event') and isinstance(event['event'], str):
                    timestamp = event.get('timestamp', 'Unknown')
                    raw_event = event['event']

                    app_match = re.search(r'for ([^,]+)', raw_event)
                    app_path = app_match.group(1).strip() if app_match else ''

                    key = (timestamp, app_path)
                    if key in seen_events:
                        continue
                    seen_events.add(key)

                    lulu_events.append(f"- [{timestamp}] {raw_event}")
                    lulu_events.append("")

            if lulu_events:
                sections.extend(lulu_events)
            else:
                sections.append("No network connection events detected")
        else:
            sections.append("No network connection events detected")
        sections.append("```")
        return sections

    def _format_xprotect_section(self, tool_events):
        """Format XProtect events section."""
        sections = [
            "",
            "### XPROTECT",
            "```"
        ]

        if "XPROTECT" in tool_events and tool_events["XPROTECT"]:
            xprotect_events = []
            seen_events = set()

            for event in tool_events["XPROTECT"]:
                try:
                    timestamp = event.get('timestamp', 'Unknown')
                    event_type = event.get('event_type', 'Unknown')

                    key = (timestamp, event_type, event.get('file_path', ''), event.get('threat_name', ''))
                    if key in seen_events:
                        continue
                    seen_events.add(key)

                    if event_type == 'malware_detection':
                        threat_name = event.get('threat_name', 'Unknown')
                        file_path = event.get('file_path', 'Unknown')
                        event_entry = [f"- [{timestamp}] 🚨 XProtect MALWARE DETECTED: {threat_name}"]
                        if file_path != 'Unknown':
                            event_entry.append(f"  - File: {file_path}")

                    elif event_type == 'quarantine_action':
                        file_path = event.get('file_path', 'Unknown')
                        action = event.get('action', 'quarantined')
                        event_entry = [f"- [{timestamp}] 🔒 XProtect {action}: {os.path.basename(file_path)}"]
                        if file_path != 'Unknown':
                            event_entry.append(f"  - File: {file_path}")

                    elif event_type == 'update':
                        event_entry = [f"- [{timestamp}] ⬇️ XProtect update detected"]
                        update_info = event.get('update_info', '')
                        if update_info:
                            event_entry.append(f"  - Update: {update_info}")

                    elif event_type == 'scan':
                        scan_type = event.get('scan_type', 'scan')
                        event_entry = [f"- [{timestamp}] 🔍 XProtect {scan_type} performed"]
                        scan_target = event.get('scan_target', '')
                        if scan_target:
                            event_entry.append(f"  - Target: {scan_target}")

                    else:
                        activity = event.get('activity', 'activity detected')
                        event_entry = [f"- [{timestamp}] XProtect {activity}"]

                    xprotect_events.extend(event_entry)
                    xprotect_events.append("")

                except Exception as e:
                    logger.error(f"Error processing XProtect event: {e}")
                    continue

            if xprotect_events:
                sections.extend(xprotect_events)
            else:
                sections.append("No XProtect events detected")
        else:
            sections.append("No XProtect events detected")
        sections.append("```")
        return sections

    def _format_ransomwhere_section(self, tool_events):
        """Format RansomWhere events section with each event listed separately.

        Supports v1.9.0+ streaming events and v2.0+ Endpoint Security framework events.
        """
        sections = [
            "",
            "### RANSOMWHERE",
            "```"
        ]

        if "RANSOMWHERE" not in tool_events or not tool_events["RANSOMWHERE"]:
            sections.append("No ransomware detection events detected")
            sections.append("```")
            return sections

        # Extract only alert response events
        alert_events = [
            event for event in tool_events["RANSOMWHERE"]
            if isinstance(event.get('event'), dict)
            and event['event'].get('type') == 'alert_response'
        ]

        # De-duplicate alerts with identical content (same path, action, args, encrypted files)
        seen_keys = set()
        unique_alerts = []
        for event in alert_events:
            details = event['event'].get('details', {})
            key = (
                details.get('path', ''),
                details.get('user_action', ''),
                tuple(details.get('args', [])),
                tuple(sorted(details.get('encryptedFiles', [])))
            )
            if key not in seen_keys:
                seen_keys.add(key)
                unique_alerts.append(event)
        alert_events = unique_alerts

        # --- Alert Events ---
        if alert_events:
            for idx, event in enumerate(alert_events, 1):
                details = event['event'].get('details', {})
                timestamp = event.get('timestamp', 'Unknown')
                user_action = details.get('user_action', 'unknown')
                severity = details.get('severity', 'medium')
                app_path = details.get('path', 'Unknown')
                message = details.get('message', '')
                pid = details.get('pid')
                pid_version = details.get('pidVersion')
                args = details.get('args', [])
                encrypted_files = details.get('encryptedFiles', [])
                encrypted_count = details.get('encrypted_file_count', 0)
                ancestors = details.get('processAncestors', [])

                if user_action == "allow":
                    action_emoji = "✅"
                elif user_action in ("block", "terminate"):
                    action_emoji = "🚫"
                else:
                    action_emoji = "⚠️"

                sections.append(f"\nRansomWhere Alert #{idx}")
                sections.append(f"  Timestamp: {timestamp}")
                sections.append(f"  {action_emoji} User {user_action}ed application")
                sections.append(f"  Severity: {severity}")

                if message:
                    sections.append(f"  Message: {message}")

                sections.append(f"  Path: {app_path}")

                if pid is not None:
                    sections.append(f"  PID: {pid}")
                if pid_version is not None:
                    sections.append(f"  PID Version: {pid_version}")

                if args:
                    sections.append("  Arguments:")
                    for arg in args:
                        sections.append(f"    • {arg}")

                if encrypted_count > 0:
                    sections.append(f"  Encrypted Files ({encrypted_count}):")
                    display_files = encrypted_files[:20] if len(encrypted_files) > 20 else encrypted_files
                    for file_path in display_files:
                        sections.append(f"    • {file_path}")
                    if len(encrypted_files) > 20:
                        sections.append(f"    ... and {len(encrypted_files) - 20} more")

                if ancestors:
                    sections.append("  Process Ancestors:")
                    for anc in ancestors:
                        name = anc.get('name', 'Unknown')
                        anc_pid = anc.get('pid', '?')
                        index = anc.get('index', '?')
                        sections.append(f"    [{index}] {name} (PID: {anc_pid})")

        if not alert_events:
            sections.append("No ransomware detection events detected")

        sections.append("```")
        return sections

    def _format_oversight_section(self, tool_events):
        """Format OverSight events section."""
        sections = [
            "",
            "### OVERSIGHT",
            "```"
        ]

        if "OVERSIGHT" in tool_events and tool_events["OVERSIGHT"]:
            for event in tool_events["OVERSIGHT"]:
                if event.get('event'):
                    sections.append(event['event'])
        else:
            sections.append("No camera/microphone access events detected")
        sections.append("```")
        return sections

    def _format_reikey_section(self, tool_events):
        """Format ReiKey events section."""
        sections = [
            "",
            "### REIKEY",
            "```"
        ]

        if "REIKEY" in tool_events and any(event.get('event') for event in tool_events["REIKEY"]):
            for event in tool_events["REIKEY"]:
                if event.get('event'):
                    sections.append(event['event'].strip())
        else:
            sections.append("No keyboard monitoring events detected")
        sections.append("```")
        return sections

    def _format_login_item_details(self, item):
        """Format details for a single login item.

        Args:
            item: Dictionary containing login item information

        Returns:
            list: Formatted item lines
        """
        lines = []
        lines.append(f"- {item['summary']}")
        lines.append("  Details:")
        for detail in item['details']:
            lines.append(f"    • {detail}")
        lines.append("")
        lines.append("  Full BTM Section:")
        lines.append("")
        lines.append(self.INDENTED_CODE_BLOCK)
        for line in item['raw_btm_section'].split('\n'):
            lines.append(f"    {line}")
        lines.append(self.INDENTED_CODE_BLOCK)
        lines.append("")
        return lines

    def _categorize_login_items(self, login_items):
        """Categorize login items into managed, non-managed, and file changes.

        Args:
            login_items: List of login items

        Returns:
            tuple: (managed_items, non_managed_items, file_changes)
        """
        managed_items = []
        non_managed_items = []
        file_changes = []

        for item in login_items:
            if isinstance(item, dict):
                if item.get('is_managed', False):
                    managed_items.append(item)
                else:
                    non_managed_items.append(item)
            else:
                file_changes.append(item)

        return managed_items, non_managed_items, file_changes

    def _format_login_items_section(self):
        """Format Managed Login Items section."""
        sections = [
            "",
            "### Managed Login Items",
            "```"
        ]

        if "system_changes" in self.report_data:
            login_items = self.report_data["system_changes"].get("login_items", [])
            if isinstance(login_items, list) and login_items:
                # Separate managed and non-managed items
                managed_items, non_managed_items, file_changes = self._categorize_login_items(login_items)

                # Display managed items first
                if managed_items:
                    for item in managed_items:
                        sections.extend(self._format_login_item_details(item))

                # Display non-managed BTM items
                if non_managed_items:
                    sections.append("")
                    sections.append("Non-Managed Login Items:")
                    for item in non_managed_items:
                        sections.extend(self._format_login_item_details(item))

                # Display file system changes
                if file_changes:
                    sections.append("")
                    sections.append("File System Changes:")
                    for item in file_changes:
                        sections.append(f"- {item}")

                if not managed_items and not non_managed_items and not file_changes:
                    sections.append(self.NO_LOGIN_ITEMS_CHANGES)
            else:
                sections.append(self.NO_LOGIN_ITEMS_CHANGES)
        else:
            sections.append(self.NO_LOGIN_ITEMS_CHANGES)
        sections.append("```")
        return sections

    def _format_notification_changes_section(self):
        """Format Notification Changes section."""
        sections = [
            "",
            "### Notification Changes",
            "```"
        ]

        if "system_changes" in self.report_data:
            notifications = self.report_data["system_changes"].get("notifications", [])
            if isinstance(notifications, list) and notifications:
                # Group changes by bundle ID base
                grouped_changes = {}
                for change in notifications:
                    base_id = '.'.join(change['bundle_id'].split('.')[:3])
                    if base_id not in grouped_changes:
                        grouped_changes[base_id] = []
                    grouped_changes[base_id].append(change)

                # Output changes grouped by application
                for base_id, app_changes in grouped_changes.items():
                    sections.append(f"\nApplication: {base_id}")
                    for change in app_changes:
                        sections.append(f"  - {change['details']}")
                        if change.get('path'):
                            sections.append(f"    Path: {change['path']}")
                        if change.get('type') == 'activity':
                            sections.append(
                                f"    Last notification: "
                                f"{change['last_notification']}"
                            )
            else:
                sections.append("No notification changes detected")
        else:
            sections.append("No notification changes detected")
        sections.append("```")
        return sections

    def _format_uninstall_results_section(self):
        """Format Uninstall Results section."""
        sections = [
            "",
            "## Uninstall Results",
            "```"
        ]

        if self.report_data.get("uninstall_results"):
            for result in self.report_data["uninstall_results"]:
                sections.append(f"- {result}")
        else:
            sections.append("No uninstallation results available")
        sections.append("```")
        return sections

    def _format_code_signing_section(self):
        """Format Code Signing Results section."""
        sections = [
            "",
            "## Code Signing Results",
            "```"
        ]

        if "code_signing_results" in self.report_data and self.report_data["code_signing_results"]:
            for result in self.report_data["code_signing_results"]:
                sections.append(f"\nApplication: {result['path']}")
                sections.append("\nFull Signing Information:")
                sections.append(result["full_info"])
                if result.get("identifiers"):
                    sections.append("\nIdentifiers:")
                    for identifier in result["identifiers"]:
                        sections.append(identifier)
                sections.append("\n" + "-" * 64)
        else:
            sections.append("No code signing results available")

        sections.append("```")
        return sections

    def _format_profile_app_name(self, profile):
        """Format application name for a configuration profile.

        Args:
            profile: Dictionary containing profile information

        Returns:
            str: Formatted application line
        """
        if 'app_name' in profile:
            return f"Application: {profile['app_name']}"
        elif 'apps' in profile and profile['apps']:
            return f"Applications: {', '.join(profile['apps'])}"
        else:
            return "Application: Unknown"

    def _format_profile_details(self, profile, payload):
        """Format profile-specific details based on type.

        Args:
            profile: Dictionary containing profile information
            payload: Payload content dictionary

        Returns:
            list: Formatted profile detail lines
        """
        lines = []
        profile_type = profile['type']

        if profile_type == 'PPPC':
            services = payload.get('Services', {})
            if services:
                lines.append("PPPC Services:")
                for service, items in services.items():
                    lines.append(f"  - {service}: {len(items)} item(s)")

        elif profile_type in ['System Extensions', 'Kernel Extensions']:
            team_ids = payload.get('AllowedTeamIdentifiers', [])
            if team_ids:
                lines.append(f"Allowed Team IDs: {', '.join(team_ids)}")

        elif profile_type == 'Notifications':
            notification_settings = payload.get('NotificationSettings', [])
            if notification_settings:
                bundle_id = notification_settings[0].get('BundleIdentifier', '')
                lines.append(f"Bundle ID: {bundle_id}")

        elif profile_type == 'Screen Recording':
            services = payload.get('Services', {})
            if 'ScreenCapture' in services:
                items = services['ScreenCapture']
                if items:
                    lines.append(f"Bundle ID: {items[0].get('Identifier', '')}")

        elif profile_type == 'Managed Login Items':
            managed_items = payload.get('ManagedLoginItems', [])
            lines.append(f"Login Items: {len(managed_items)} item(s)")
            for item in managed_items:
                lines.append(f"  - {item.get('BundleIdentifier', '')}")

        return lines

    def _format_configuration_profiles_section(self):
        """Format Configuration Profiles section."""
        sections = [
            "",
            "## Configuration Profiles Generated",
            ""
        ]

        if "configuration_profiles" in self.report_data and self.report_data["configuration_profiles"]:
            profile_data = self.report_data["configuration_profiles"]

            # Add detailed information about generated profiles
            if profile_data.get("generated_profiles"):
                sections.extend([
                    "### Generated Profile Details",
                    "```"
                ])

                for profile in profile_data["generated_profiles"]:
                    sections.append(f"\nProfile Type: {profile['type']}")
                    sections.append(f"Filename: {profile['filename']}")
                    sections.append(self._format_profile_app_name(profile))

                    # Add profile-specific details based on type
                    profile_content = profile.get('profile', {})
                    payload_content = profile_content.get('PayloadContent', [])

                    if payload_content:
                        payload = payload_content[0]
                        sections.extend(self._format_profile_details(profile, payload))

                    sections.append("")

                sections.append("```")
        else:
            sections.append("No configuration profiles were generated during this test.")
            sections.append("")
            sections.append("ℹ️  **Note**: Even when no profiles are auto-generated, consider manual review")
            sections.append("   for application-specific configuration requirements that may not be detected.")
            sections.append("")

        return sections

    def _format_pkg_basic_info(self, pkg_name, pkg_info, dmg_info):
        """Format basic package information.

        Args:
            pkg_name: Package name
            pkg_info: Dictionary with package info
            dmg_info: Dictionary with DMG info

        Returns:
            list: Formatted basic info lines
        """
        lines = [f"Package: {pkg_name}"]
        if pkg_info.get("identifier"):
            lines.append(f"  Identifier: {pkg_info['identifier']}")
        if pkg_info.get("version"):
            lines.append(f"  Version: {pkg_info['version']}")
        if pkg_info.get("type"):
            lines.append(f"  Type: {pkg_info['type']}")
        if dmg_info:
            lines.append(f"  DMG Source: {dmg_info.get('name', 'unknown')}")
        return lines

    def _format_pkg_components(self, components, deprecated_deps, critical_issues):
        """Format component information for distribution packages.

        Args:
            components: List of components
            deprecated_deps: List of deprecated dependencies
            critical_issues: List of critical issues

        Returns:
            list: Formatted component lines
        """
        lines = []
        if components:
            enabled_count = sum(1 for comp in components if comp.get("status") == "enabled")
            disabled_count = len(components) - enabled_count
            lines.append(f"  Components: {len(components)} total ({enabled_count} enabled, {disabled_count} disabled)")

            # Show components with issues
            components_with_issues = []
            for dep in deprecated_deps:
                if dep.get("component"):
                    components_with_issues.append(dep["component"])
            for crit in critical_issues:
                if crit.get("component"):
                    components_with_issues.append(crit["component"])

            if components_with_issues:
                unique_components = list(set(components_with_issues))
                lines.append(f"  Components with issues: {', '.join(unique_components)}")

        return lines

    def _format_pkg_deprecated_deps(self, deprecated_deps):
        """Format deprecated dependencies.

        Args:
            deprecated_deps: List of deprecated dependencies

        Returns:
            list: Formatted deprecated dependency lines
        """
        lines = []
        if deprecated_deps:
            lines.append("  Deprecated dependencies:")
            for dep in deprecated_deps:
                script = dep.get("script", "unknown")
                shebang = dep.get("shebang", "unknown")
                component = dep.get("component")
                if component:
                    lines.append(f"    - {script}: {shebang} (in {component})")
                else:
                    lines.append(f"    - {script}: {shebang}")
        return lines

    def _format_pkg_critical_issues(self, critical_issues):
        """Format critical issues.

        Args:
            critical_issues: List of critical issues

        Returns:
            list: Formatted critical issue lines
        """
        lines = []
        if critical_issues:
            lines.append("  Critical issues:")
            for issue in critical_issues:
                script = issue.get("script", "unknown")
                description = issue.get("description", "unknown issue")
                component = issue.get("component")
                component_info = f" (in {component})" if component else ""
                if issue.get("shebang"):
                    lines.append(f"    - {script}: {issue['shebang']} ({description}){component_info}")
                else:
                    lines.append(f"    - {script}: {description}{component_info}")
        return lines

    def _format_pkg_python_usage(self, python_usage):
        """Format Python usage information.

        Args:
            python_usage: List of Python usage items

        Returns:
            list: Formatted Python usage lines
        """
        lines = []
        if python_usage:
            lines.append("  Python references found:")
            for usage in python_usage:
                script = usage.get("script", "unknown")
                component = usage.get("component")
                component_info = f" (in {component})" if component else ""
                lines.append(f"    - {script}{component_info}")
        return lines

    def _format_package_analysis_section(self):
        """Format Package Analysis section."""
        sections = []

        if "package_analysis" in self.report_data:
            package_data = self.report_data["package_analysis"]

            # Display summary
            packages_found = package_data.get("packages_found", 0)
            total_issues = package_data.get("total_issues", 0)
            critical_issues = package_data.get("critical_issues", 0)

            sections.extend([
                f"Packages analyzed: {packages_found}",
                f"Total deprecated dependency issues: {total_issues}",
                f"Critical issues (Python 2 usage): {critical_issues}",
                ""
            ])

            if package_data.get("analysis_results"):
                # Display detailed results for packages with issues
                packages_with_issues = [
                    result for result in package_data["analysis_results"]
                    if result.get("deprecated_dependencies") or result.get("critical_issues")
                ]

                if packages_with_issues:
                    sections.append("Packages with deprecated dependencies:")
                    sections.append("")

                    for result in packages_with_issues:
                        pkg_name = result.get("package_name", "Unknown")
                        pkg_info = result.get("package_info", {})
                        components = result.get("components", [])
                        dmg_info = result.get("dmg_info", {})
                        deprecated = result.get("deprecated_dependencies", [])
                        critical = result.get("critical_issues", [])
                        python_usage = result.get("python_usage", [])

                        sections.extend(self._format_pkg_basic_info(pkg_name, pkg_info, dmg_info))
                        sections.extend(self._format_pkg_components(components, deprecated, critical))
                        sections.extend(self._format_pkg_deprecated_deps(deprecated))
                        sections.extend(self._format_pkg_critical_issues(critical))
                        sections.extend(self._format_pkg_python_usage(python_usage))
                        sections.append("")
                else:
                    sections.append("No deprecated dependencies found.")
            else:
                sections.append("No packages were analyzed.")
        else:
            sections.append("Package analysis was not performed during this test.")

        return sections

    def _format_virustotal_network_section(self, tool_events):
        """Format VirusTotal Network Analysis section."""
        sections = [
            "",
            "### VirusTotal Network Analysis",
            "```"
        ]

        if "VIRUSTOTAL" in tool_events and tool_events["VIRUSTOTAL"]:
            vt_network_events = []
            seen_events = set()

            for event in tool_events["VIRUSTOTAL"]:
                timestamp = event.get('timestamp', 'Unknown')
                event_text = event.get('event', '')
                details = event.get('details', {})

                # Skip duplicates based on URL and status
                scanned_url = details.get('scanned_url', '')
                status = details.get('status', 'unknown')
                key = (scanned_url, status)

                if key in seen_events:
                    continue
                seen_events.add(key)

                # Format the network analysis result
                if 'Network scan:' in event_text:
                    vt_network_events.append(f"- [{timestamp}] {event_text}")

                    # Add additional details if available
                    if details:
                        scan_results = details.get('scan_results', {})
                        malicious = scan_results.get('malicious', 0)
                        suspicious = scan_results.get('suspicious', 0)

                        if status == 'malicious' and malicious > 0:
                            vt_network_events.append(f"  - ⚠️  Action required: Investigate connection flagged by {malicious} vendor(s)")
                        elif status == 'suspicious' and suspicious > 0:
                            vt_network_events.append(f"  - ⚠️  Action required: Review connection flagged by {suspicious} vendor(s)")
                        elif status == 'clean':
                            vt_network_events.append("  - ✅ Connection appears clean (not flagged by any vendors)")

                        # Add permalink if available
                        permalink = details.get('permalink')
                        if permalink:
                            vt_network_events.append(f"  - Report: {permalink}")

                    vt_network_events.append("")

            if vt_network_events:
                sections.extend(vt_network_events)
            else:
                sections.append("No network connections scanned")
        else:
            sections.append("No network connections scanned")

        sections.extend([
            "```",
            ""
        ])

        return sections

    def _format_knockknock_section(self):
        """Format KnockKnock Persistence Analysis section.

        KnockKnock v4.0.0+ Features:
        - Shell Configuration Files detection (persistence in ~/.zshrc, etc.)
        - VirusTotal v3 API integration with user keys
        - Improved JSON export format (#42)

        KnockKnock v4.0.2+:
        - Enhanced comparison logic (#45) for more accurate change detection

        KnockKnock v4.0.3+:
        - Improved BTM enumeration (#23)
        - Better UI for persistence item display
        """
        sections = []

        if "knockknock_results" in self.report_data and self.report_data.get('knockknock_available'):
            sections.extend([
                "### KnockKnock Persistence Analysis",
                "```"
            ])

            kk_results = self.report_data["knockknock_results"]

            # Check for error
            if "error" in kk_results:
                sections.extend([
                    f"❌ KnockKnock analysis failed: {kk_results['error']}",
                    "```",
                    ""
                ])
            else:
                summary = kk_results.get("summary", {})
                comparison = kk_results.get("comparison", {})

                # Display summary
                sections.append("Scan Summary:")
                sections.append(f"  Baseline items: {summary.get('baseline_total', 0)}")
                sections.append(f"  Post-install items: {summary.get('post_install_total', 0)}")
                sections.append("")

                sections.append("Changes Detected:")
                new_count = comparison.get('new_count', 0)
                modified_count = comparison.get('modified_count', 0)
                removed_count = comparison.get('removed_count', 0)

                sections.append(f"  • New persistence items: {new_count}")
                sections.append(f"  • Modified items: {modified_count}")
                sections.append(f"  • Removed items: {removed_count}")
                sections.append("")

                # Display new items with VirusTotal results
                if new_count > 0:
                    sections.append("New Persistence Items:")
                    sections.append("-" * 60)

                    for new_item in comparison.get('new_items', []):
                        category = new_item.get('category', 'Unknown')
                        item = new_item.get('item', {})

                        sections.append(f"\n• Category: {category}")

                        # Display all available item details
                        for key, value in item.items():
                            # Skip VirusTotal and signing info (not available when VT is disabled)
                            if key in ['virusTotal', 'signing info']:
                                continue
                            elif isinstance(value, (str, int, float, bool)):
                                # Display simple key-value pairs
                                sections.append(f"  {key}: {value}")
                            elif isinstance(value, list):
                                # Display list items
                                sections.append(f"  {key}: {', '.join(str(v) for v in value)}")

                sections.append("```")
                sections.append("")
        elif self.report_data.get('knockknock_available') is False:
            sections.extend([
                "### KnockKnock Persistence Analysis",
                "```",
                "KnockKnock not installed - persistence analysis skipped.",
                "Install KnockKnock for automated persistence mechanism detection.",
                "```",
                ""
            ])

        return sections

    def _format_system_info_header(self):
        """Format system information header section.

        Returns:
            list: Formatted system info lines
        """
        system_info = self.report_data['system_info']
        os_version = system_info.get('os_version_full', system_info.get('os_version', 'Unknown'))

        return [
            "## System Information",
            "```",
            f"- Detected macOS version: {os_version}",
            f"- Detected architecture: {system_info.get('architecture', 'Unknown')}",
            f"- Detected Munki version: {system_info.get('munki_version', 'Unknown')}",
            f"- Console user: {system_info.get('console_user', 'Unknown')}",
            f"- User admin status: {system_info.get('user_admin_status', 'Unknown')}",
            f"- Model Identifier: {system_info.get('model_identifier', 'Unknown')}",
            f"- System type: {system_info.get('system_type', 'Unknown')}",
            f"- Serial number: {system_info.get('serial_number', 'Unknown')}",
            ""
        ]

    def _format_security_tools_info(self):
        """Format security tools and XProtect information.

        Returns:
            list: Formatted security tools lines
        """
        lines = []
        security_tools = self.report_data['system_info'].get('security_tool_versions', {})

        if security_tools:
            lines.append(f"- Security tools detected: {len(security_tools)} tools")
            for tool_name, version in security_tools.items():
                lines.append(f"  - {tool_name}: {version}")
        else:
            lines.append("- Security tools detected: 0 tools")

        # Add XProtect status information
        xprotect_status = self.report_data['system_info'].get('xprotect_status', {})
        if xprotect_status and "error" not in xprotect_status:
            lines.append("")
            lines.append("XProtect Configuration:")
            lines.append(f"  - Launch scans: {xprotect_status.get('launch_scans', 'unknown')}")
            lines.append(f"  - Background scans: {xprotect_status.get('background_scans', 'unknown')}")

        return lines

    def _format_vm_warning(self):
        """Format virtual machine warning if applicable.

        Returns:
            list: VM warning lines (empty if not a VM)
        """
        system_type = self.report_data['system_info'].get('system_type', '')
        if system_type and 'Virtual Machine' in system_type:
            return [
                "",
                "⚠️  WARNING: Virtual Machine Detected",
                "   Some software may not install or work correctly on virtual machines.",
                "   Malware often detects VMs and may remain dormant during testing.",
                "   Consider testing on a dedicated physical test computer for more",
                "   accurate results, especially when testing security software."
            ]
        return []

    def _format_rosetta_section(self):
        """Format Rosetta compatibility information.

        Returns:
            list: Rosetta info lines (empty if not available)
        """
        if 'rosetta_info' not in self.report_data:
            return []

        lines = ["", "Rosetta Compatibility:"]
        rosetta_info = self.report_data['rosetta_info']

        for app_path, info in rosetta_info.items():
            app_name = app_path.split('/')[-1]
            lines.append(f"  {app_name}:")

            detection_method = info.get('detection_method')
            if detection_method in ['intel_system_skipped', 'intel_system_no_arch_info']:
                # Intel system - show architecture information if available
                if info.get('detection_supported'):
                    reason = info.get('rosetta_reason', '')
                    lines.append(f"    - {reason}")
                else:
                    lines.append("    - Intel system - no architecture information available")
            elif info.get('detection_supported'):
                if info.get('requires_rosetta'):
                    lines.append(f"    - Requires Rosetta: {info.get('rosetta_reason', 'Unknown reason')}")
                    if info.get('rosetta_override'):
                        lines.append(f"    - Override type: {info.get('rosetta_override')}")
                    if not info.get('has_native_version', True):
                        lines.append("    - No native Apple Silicon version available")
                else:
                    lines.append("    - Runs natively on Apple Silicon")
                    reason = info.get('rosetta_reason')
                    if reason:
                        lines.append(f"      {reason}")
            else:
                lines.append("    - Rosetta detection not supported on this macOS version")

        return lines

    def _format_test_results_details(self):
        """Format test results section including loop tests.

        Returns:
            list: Formatted test results lines
        """
        lines = []

        # Add main test results first
        for result in self.report_data.get("test_results", []):
            lines.append(f"- {result}")

        # Add Loop Install Test Results with better formatting
        if "loop_install_test" in self.report_data:
            test_data = self.report_data["loop_install_test"]
            lines.extend([
                "",
                "Loop Install Test Results:",
                f"Status: {test_data.get('status', 'unknown').upper()}",
                f"Time: {test_data.get('timestamp', '')}",
                "",
                "Details:"
            ])
            for detail in test_data.get("details", []):
                lines.append(f"  • {detail}")

        # Add Loop Uninstall Test Results with better formatting
        if "loop_uninstall_test" in self.report_data:
            test_data = self.report_data["loop_uninstall_test"]
            lines.extend([
                "",
                "Loop Uninstall Test Results:",
                f"Status: {test_data.get('status', 'unknown').upper()}",
                f"Time: {test_data.get('timestamp', '')}",
                "",
                "Details:"
            ])
            for detail in test_data.get("details", []):
                lines.append(f"  • {detail}")

        return lines

    def _group_security_events(self):
        """Group security events by tool name.

        Returns:
            dict: Security events grouped by tool
        """
        tool_events = {}
        for event in self.report_data.get("security_events", []):
            tool = event.get('tool', '').upper()
            if tool not in tool_events:
                tool_events[tool] = []
            tool_events[tool].append(event)
        return tool_events

    def generate_report(self, app_name):
        """Generate markdown report with enhanced formatting and data processing"""
        sections = []

        # Import config manager for report title
        from ..core.config_manager import get_config
        config = get_config()
        report_title = config.get_report_title()

        # Header Section
        sections.extend([
            f"# {report_title}",
            f"Generated: {self.report_data['test_date']}",
            f"Application: {app_name}",
            ""
        ])

        # System Information
        sections.extend(self._format_system_info_header())
        sections.extend(self._format_security_tools_info())
        sections.extend(self._format_vm_warning())

        sections.extend([
            "```",
            ""
        ])

        # Rosetta Compatibility (as separate section)
        rosetta_lines = self._format_rosetta_section()
        if rosetta_lines:
            sections.append("## Rosetta Compatibility")
            sections.append("```")
            sections.extend(rosetta_lines[2:])  # Skip the empty line and "Rosetta Compatibility:" line
            sections.extend([
                "```",
                ""
            ])

        sections.extend([
            "## Catalog Validation",
            "```"
        ])

        # Add catalog validation results
        if 'catalog_validation' in self.report_data:
            for result in self.report_data['catalog_validation']:
                sections.append(f"- {result}")
        else:
            sections.append("No catalog validation results available")

        sections.extend([
            "```",
            "",
            "## Installation Details",
            "```"
        ])

        # Installation Details
        for detail in self.report_data.get('install_details', []):
            sections.append(f"- {detail}")
        sections.append("```")

        # Test Results
        sections.extend([
            "",
            "## Test Results",
            "```"
        ])

        sections.extend(self._format_test_results_details())
        sections.append("```")

        # Package Analysis (as separate section)
        package_lines = self._format_package_analysis_section()
        if package_lines:
            sections.append("")
            sections.append("## Package Analysis")
            sections.append("```")
            sections.extend(package_lines)
            sections.append("```")

        # Security Events Section
        sections.extend(["", "## Security Events"])
        sections.extend(self._format_virustotal_section())
        sections.extend(self._format_threatlabs_section())

        # Group events by tool for network and other tools
        tool_events = self._group_security_events()
        sections.extend(self._format_virustotal_network_section(tool_events))
        sections.extend(self._format_knockknock_section())
        sections.extend(self._format_security_tool_sections(tool_events))

        # System Changes
        sections.extend([
            "",
            "## System Changes",
            "",
            "### System Extensions",
            "```"
        ])

        if "system_changes" in self.report_data:
            if isinstance(self.report_data["system_changes"], dict):
                sysext = self.report_data["system_changes"].get("system_extensions")
                if isinstance(sysext, list) and sysext:
                    for ext in sysext:
                        sections.append(ext)
                else:
                    sections.append(self.NO_SYSTEM_EXTENSIONS)
            else:
                sections.append(self.NO_SYSTEM_EXTENSIONS)
        else:
            sections.append(self.NO_SYSTEM_EXTENSIONS)
        sections.append("```")

        # Add Managed Login Items section
        sections.extend(self._format_login_items_section())

        # Add Notification Changes section
        sections.extend(self._format_notification_changes_section())

        # Add Uninstall Results section
        sections.extend(self._format_uninstall_results_section())

        # Add Code Signing Results section
        sections.extend(self._format_code_signing_section())

        # Add Configuration Profiles section
        sections.extend(self._format_configuration_profiles_section())

        return "\n".join(sections)
