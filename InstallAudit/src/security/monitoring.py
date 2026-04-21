# Copyright (c) 2026 Paul Cossey. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
"""
Security monitoring module for managing real-time security tool monitoring.
"""

import subprocess
import os
import time
import threading
import queue
import re
import json
import logging
from datetime import datetime
from ..core.config import DEFAULT_LOG_LOOKBACK_MINUTES

# Set up logging
logger = logging.getLogger(__name__)


class SecurityMonitoring:
    # Constants for duplicated string literals
    USER_SAYS = "user says"
    USER_SAYS_ALLOW = "user says, 'allow'"
    USER_SAYS_BLOCK = "user says, 'block'"
    BINARY_PATH_KEY = 'binary path'

    def __init__(self):
        """Initialize the security monitoring system."""
        self.monitoring_processes = {}

        # Initialize report_data if not already present (for standalone usage)
        # In CompositeTester, AutoUpdateTester.__init__() will have already set this
        if not hasattr(self, 'report_data') or self.report_data is None:
            self.report_data = {"security_events": []}
        elif 'security_events' not in self.report_data:
            # If report_data exists but doesn't have security_events, add it
            self.report_data["security_events"] = []

        # Initialize security_tools if not already present (for standalone usage)
        # In CompositeTester, AutoUpdateTester.__init__() will have already set this
        if not hasattr(self, 'security_tools') or self.security_tools is None:
            self.security_tools = {}

        self._global_historical_collected = {}  # Track which tools have had historical events collected
        self.dhs_vt_analysis_completed = False  # Flag to prevent duplicate DHS VirusTotal analysis

        # RansomWhere multi-line stream buffering
        self._ransomwhere_encrypted_files = []  # Buffer for encrypted files from isEncrypted checks
        self._ransomwhere_in_alert = False  # Track if currently parsing alert dictionary
        self._ransomwhere_alert_buffer = []  # Raw continuation lines of current alert dict
        self._ransomwhere_alert_fields = {}  # Parsed structured fields from alert dict
        self._ransomwhere_last_checked_path = None  # Last path from isEncrypted check

    def _start_reader_thread(self, tool_name, process_info):
        """Start a dedicated thread that reads lines from subprocess stdout into a queue.

        Using a queue avoids the select.select + TextIOWrapper buffering issue where
        select operates on the raw fd but readline uses Python's internal buffer,
        causing lines to be missed when select reports 'not ready' despite buffered data.

        Args:
            tool_name: Name of the security tool
            process_info: Process information dict
        """
        line_queue = queue.Queue()
        process_info["line_queue"] = line_queue

        def reader():
            try:
                for line in process_info["process"].stdout:
                    line_queue.put(line)
            except (OSError, ValueError):
                pass
            line_queue.put(None)  # Sentinel to signal EOF

        reader_thread = threading.Thread(target=reader, daemon=True, name=f"{tool_name}-reader")
        reader_thread.start()
        process_info["reader_thread"] = reader_thread

    def _monitor_single_process(self, tool_name, process_info):
        """Monitor a single process for output by reading from its line queue.

        Processes all currently available lines (up to 200 per cycle) from the
        queue filled by the dedicated reader thread.

        Args:
            tool_name: Name of the tool
            process_info: Process information dict
        """
        if not process_info.get("active", False):
            return

        try:
            line_queue = process_info.get("line_queue")
            if not line_queue:
                return

            # Process all available lines from the queue (up to 200 per cycle)
            lines_processed = 0
            while lines_processed < 200:
                try:
                    line = line_queue.get_nowait()
                except queue.Empty:
                    break
                if line is None:  # EOF sentinel from reader thread
                    process_info["active"] = False
                    break
                self._process_stream_line(tool_name, line.strip(), process_info)
                lines_processed += 1

        except Exception as e:
            logger.error(f"Error monitoring {tool_name}: {e}")
            process_info["active"] = False

    def _start_continuous_monitoring(self):
        """Start continuous monitoring thread for real-time log streaming."""
        def monitor_streams():
            """Monitor streaming processes for real-time events."""
            while any(proc_info.get("active", False) for proc_info in self.monitoring_processes.values()):
                for tool_name, process_info in self.monitoring_processes.items():
                    self._monitor_single_process(tool_name, process_info)
                time.sleep(0.5)  # Small delay to prevent excessive CPU usage

        # Start the monitoring thread if needed
        if any(self.security_tools[tool]["type"] in ["stream", "both"] for tool in self.monitoring_processes.keys()):
            monitor_thread = threading.Thread(target=monitor_streams, daemon=True)
            monitor_thread.start()

    def _process_lulu_stream_line(self, line, timestamp, process_info):
        """Process LuLu log stream events.

        LuLu v4.2.1+ Features:
        - Rule duration is now relative rather than fixed end time
        - User-created rules can be exported/imported
        - Flows for exited processes are now denied (improved security)
        - Enhanced UI for alert presentation

        Log event format remains compatible across versions.
        """
        if ("(user) response:" in line
                or self.USER_SAYS in line.lower()
                or "presenting alert" in line.lower()
                or "user clicked" in line.lower()
                or "creating rule" in line.lower()
                or "rule created" in line.lower()):
            event = {
                "tool": "LULU",
                "timestamp": timestamp,
                "event": line.strip()
            }
            process_info["events"].append(event)
            print(f"    → [{timestamp}] LuLu User Action: {line.strip()}")

    def _parse_ransomwhere_alert_buffer(self):
        """Parse the buffered alert dict lines into structured fields.

        Parses the Objective-C plist text format used by RansomWhere's alert dict,
        extracting: args, encryptedFiles, message, path, pid, pidVersion, processAncestors.
        """
        full_text = '\n'.join(self._ransomwhere_alert_buffer)
        fields = {}

        # Extract args array
        args_match = re.search(r'args\s*=\s*\((.*?)\)\s*;', full_text, re.DOTALL)
        if args_match:
            fields['args'] = re.findall(r'"([^"]+)"', args_match.group(1))

        # Extract encryptedFiles array
        ef_match = re.search(r'encryptedFiles\s*=\s*\((.*?)\)\s*;', full_text, re.DOTALL)
        if ef_match:
            fields['encryptedFiles'] = re.findall(r'"([^"]+)"', ef_match.group(1))

        # Extract message
        msg_match = re.search(r'message\s*=\s*"([^"]*)"\s*;', full_text)
        if msg_match:
            fields['message'] = msg_match.group(1)

        # Extract path (use negative lookbehind to avoid matching inside nested keys)
        path_match = re.search(r'(?<![a-zA-Z])path\s*=\s*"([^"]*)"\s*;', full_text)
        if path_match:
            fields['path'] = path_match.group(1)

        # Extract pid (top-level only, not nested)
        pid_match = re.search(r'(?<![a-zA-Z])pid\s*=\s*(\d+)\s*;', full_text)
        if pid_match:
            fields['pid'] = int(pid_match.group(1))

        # Extract pidVersion
        pv_match = re.search(r'pidVersion\s*=\s*(\d+)\s*;', full_text)
        if pv_match:
            fields['pidVersion'] = int(pv_match.group(1))

        # Extract processAncestors as list of dicts
        pa_match = re.search(r'processAncestors\s*=\s*\((.*?)\)\s*;', full_text, re.DOTALL)
        if pa_match:
            ancestors = []
            for dict_match in re.finditer(r'\{([^}]+)\}', pa_match.group(1)):
                ancestor = {}
                for kv_match in re.finditer(
                    r'(\w+)\s*=\s*(?:"([^"]*)"|([\d]+))\s*;', dict_match.group(1)
                ):
                    key = kv_match.group(1)
                    value = kv_match.group(2) if kv_match.group(2) is not None else int(kv_match.group(3))
                    ancestor[key] = value
                if ancestor:
                    ancestors.append(ancestor)
            fields['processAncestors'] = ancestors

        # Merge encrypted files from isEncrypted checks with alert dict's encryptedFiles
        alert_files = fields.get('encryptedFiles', [])
        for path in self._ransomwhere_encrypted_files:
            if path not in alert_files:
                alert_files.append(path)
        if alert_files:
            fields['encryptedFiles'] = alert_files

        self._ransomwhere_alert_fields = fields
        logger.debug(f"RansomWhere: Parsed alert fields: {list(fields.keys())}")

    def _create_ransomwhere_alert_event(self, timestamp, user_action, process_info, raw_message):
        """Create a structured RansomWhere alert event with all parsed fields."""
        fields = self._ransomwhere_alert_fields
        severity = "critical" if user_action in ("block", "terminate") else "high"
        encrypted_files = fields.get('encryptedFiles', [])
        app_path = fields.get('path', 'Unknown')

        event = {
            "tool": "RANSOMWHERE",
            "timestamp": timestamp,
            "event": {
                "type": "alert_response",
                "details": {
                    "user_action": user_action,
                    "path": app_path,
                    "args": fields.get('args', []),
                    "encryptedFiles": encrypted_files,
                    "encrypted_file_count": len(encrypted_files),
                    "message": fields.get('message', ''),
                    "pid": fields.get('pid'),
                    "pidVersion": fields.get('pidVersion'),
                    "processAncestors": fields.get('processAncestors', []),
                    "severity": severity,
                    "raw_message": raw_message
                }
            }
        }

        process_info["events"].append(event)
        display_path = os.path.basename(app_path) if app_path != "Unknown" else "Unknown"
        file_count = len(encrypted_files)
        print(f"    → [{timestamp}] RansomWhere: {user_action} - {display_path} ({file_count} encrypted files)")

        # Reset all alert state
        self._ransomwhere_encrypted_files = []
        self._ransomwhere_last_checked_path = None
        self._ransomwhere_alert_buffer = []
        self._ransomwhere_alert_fields = {}

    def _process_ransomwhere_stream_line(self, line, timestamp, process_info):
        """Process RansomWhere log stream events (v1.9.0+, v2.0+ with Endpoint Security) line-by-line with multi-line buffering.

        v2.0+ rewrite uses Apple Endpoint Security framework with improved process hierarchy.

        Captures each event separately:
        - Alert responses (allow/block/terminate) with full alert dict fields
        - Helper events as individual entries
        - Daemon events (suspended, delivering alert, etc.) as individual entries
        - Improved process hierarchy capture (v2.0.1+)
        """

        logger.debug(f"RansomWhere stream line: {line[:100]}...")

        # Check if this is a continuation line (no timestamp = part of multi-line message)
        is_continuation = not re.match(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", line)

        # Handle continuation lines within multi-line alert dict
        if is_continuation and self._ransomwhere_in_alert:
            self._ransomwhere_alert_buffer.append(line)
            return

        # If we were in an alert dict and now see a timestamped line, parse the buffered dict
        if not is_continuation and self._ransomwhere_in_alert:
            self._parse_ransomwhere_alert_buffer()
            # Don't reset _in_alert yet - wait for user response line
            # But mark dict parsing as done
            self._ransomwhere_in_alert = False

        # Skip RansomWhere Helper lines (not needed for report)
        if "RansomWhere Helper" in line and "app (helper)" in line:
            return

        # Track individual encrypted file detections from daemon
        # Pattern: isEncrypted /path: entropy=... header=yes
        if "isEncrypted" in line and "header=yes" in line:
            path_match = re.search(r'isEncrypted\s+(/.+?):\s+entropy=', line)
            if path_match:
                self._ransomwhere_last_checked_path = path_match.group(1)
            return

        if "file is encrypted, added to process" in line:
            if self._ransomwhere_last_checked_path:
                if self._ransomwhere_last_checked_path not in self._ransomwhere_encrypted_files:
                    self._ransomwhere_encrypted_files.append(self._ransomwhere_last_checked_path)
                self._ransomwhere_last_checked_path = None
            return

        # Clear last checked path on non-encrypted results
        if "IGNORING:" in line or "Not encrypted" in line:
            self._ransomwhere_last_checked_path = None
            return

        # Skip daemon info events (suspended, delivering alert, process hierarchy)
        if "suspended:" in line and "ransomwhere" in line.lower():
            return
        if "delivering alert to user" in line:
            return
        if "process hierarchy:" in line:
            return

        # Start of alert dictionary - buffer continuation lines
        if "sending alert to user (client):" in line or "responding to daemon, alert:" in line:
            self._ransomwhere_in_alert = True
            self._ransomwhere_alert_buffer = []
            self._ransomwhere_alert_fields = {}
            logger.debug("RansomWhere: Alert dict start detected")
            return

        # User response: allow
        if self.USER_SAYS_ALLOW in line:
            # If alert fields haven't been parsed yet (happens if dict and response are close)
            if self._ransomwhere_in_alert and self._ransomwhere_alert_buffer:
                self._parse_ransomwhere_alert_buffer()
                self._ransomwhere_in_alert = False

            path_match = re.search(r"allowing\s+(.+)$", line)
            process_path = path_match.group(1) if path_match else "Unknown"

            # If we didn't get a path from the alert dict, use the one from the allow line
            if not self._ransomwhere_alert_fields.get('path'):
                self._ransomwhere_alert_fields['path'] = process_path

            self._create_ransomwhere_alert_event(timestamp, "allow", process_info, line.strip())
            return

        # User response: block or terminate
        if self.USER_SAYS_BLOCK in line or "user says, 'terminate'" in line:
            if self._ransomwhere_in_alert and self._ransomwhere_alert_buffer:
                self._parse_ransomwhere_alert_buffer()
                self._ransomwhere_in_alert = False

            user_action = "terminate" if "terminate" in line else "block"

            path_match = re.search(r"(?:blocking|terminating)\s+(.+)$", line)
            process_path = path_match.group(1) if path_match else "Unknown"

            if not self._ransomwhere_alert_fields.get('path'):
                self._ransomwhere_alert_fields['path'] = process_path

            self._create_ransomwhere_alert_event(timestamp, user_action, process_info, line.strip())

    def _process_oversight_stream_line(self, line, timestamp, process_info):
        """Process OverSight log stream events."""
        if "camera" in line.lower() or "microphone" in line.lower():
            event = {
                "tool": "OVERSIGHT",
                "timestamp": timestamp,
                "event": line.strip()
            }
            process_info["events"].append(event)
            print(f"    → [{timestamp}] OverSight: {line.strip()}")

    def _parse_blockblock_event_data(self, line, timestamp):
        """Parse BlockBlock event data from log line.
        Handles both persistence events and paste protection events (v2.3.0+).

        Returns:
            dict: Parsed event data or None if parsing fails
        """
        # Check if this is a paste protection event
        if "paste" in line.lower() or "clickfix" in line.lower():
            return self._parse_paste_protection_stream_event(line, timestamp)

        # Regular persistence event
        event_data = {
            "tool": "BLOCKBLOCK",
            "timestamp": timestamp,
            "event": {
                "type": "user_action",
                "details": {
                    "action": "user_decision",
                    "timestamp": timestamp,
                    "process_path": "Unknown",
                    "path": "Unknown",
                    "raw_message": line.strip()
                }
            }
        }

        # Determine action type
        if self.USER_SAYS_ALLOW in line:
            event_data["event"]["details"]["action"] = "user_allowed"
        elif self.USER_SAYS_BLOCK in line:
            event_data["event"]["details"]["action"] = "user_blocked"

        # Extract item path
        object_match = re.search(r'object=([^,\s]+)', line)
        if object_match:
            event_data["event"]["details"]["path"] = object_match.group(1)
        else:
            item_match = re.search(r'item binary=name=([^,]+)', line)
            if item_match:
                event_data["event"]["details"]["path"] = item_match.group(1)

        # Extract process information
        self._extract_blockblock_process_info(line, event_data)

        return event_data

    def _parse_paste_protection_stream_event(self, line, timestamp):
        """Parse BlockBlock paste protection event from stream.

        Args:
            line: Log line
            timestamp: Event timestamp

        Returns:
            Parsed paste protection event dict
        """
        # Extract target application
        target_app = "Unknown"
        app_match = re.search(r'(Terminal|iTerm|iTerm2)', line, re.IGNORECASE)
        if app_match:
            target_app = app_match.group(1)

        # Determine action
        action = "alerted"
        if self.USER_SAYS_ALLOW in line or "allowed" in line.lower():
            action = "allowed"
        elif "blocked" in line.lower():
            action = "blocked"

        return {
            "tool": "BLOCKBLOCK",
            "timestamp": timestamp,
            "event": {
                "type": "paste_protection",
                "details": {
                    "action": action,
                    "target_app": target_app,
                    "timestamp": timestamp,
                    "raw_message": line.strip()
                }
            }
        }

    def _extract_blockblock_process_info(self, line, event_data):
        """Extract process information from BlockBlock log line.

        Args:
            line: Log line to parse
            event_data: Event data dict to populate
        """
        process_match = re.search(r'process="process":(\{[^\}]*\}), item file path', line)
        if process_match:
            try:
                process_json = process_match.group(1).replace('\\"', '"')
                process_info_data = json.loads(process_json)
                event_data["event"]["details"]["process_path"] = process_info_data.get("path", "Unknown")
                event_data["event"]["details"]["process_name"] = process_info_data.get("name", "Unknown")
            except (json.JSONDecodeError, AttributeError):
                # Fallback: extract manually
                name_match = re.search(r'"name":"([^"]+)"', line)
                path_match = re.search(r'"path":"([^"]+)"', line)
                if name_match:
                    event_data["event"]["details"]["process_name"] = name_match.group(1)
                if path_match:
                    event_data["event"]["details"]["process_path"] = path_match.group(1)

    def _process_blockblock_stream_line(self, line, timestamp, process_info):
        """Process BlockBlock log stream events."""
        # Check for paste protection or regular BlockBlock events
        if self.USER_SAYS not in line and "paste" not in line.lower() and "clickfix" not in line.lower():
            return

        try:
            event_data = self._parse_blockblock_event_data(line, timestamp)
            process_info["events"].append(event_data)

            # Check event type for display message
            event_type = event_data["event"].get("type", "user_action")

            if event_type == "paste_protection":
                # Display paste protection alert
                action = event_data["event"]["details"]["action"]
                target_app = event_data["event"]["details"]["target_app"]
                print(f"    → [{timestamp}] BlockBlock Paste Protection: {action} - {target_app} (ClickFix Alert)")
            else:
                # Display regular persistence event
                action = event_data["event"]["details"]["action"]
                item_name = event_data["event"]["details"]["path"]
                process_name = event_data["event"]["details"].get("process_name", "Unknown")
                display_item = os.path.basename(item_name) if item_name != "Unknown" else "unknown item"
                print(f"    → [{timestamp}] BlockBlock User Action: {action} - {display_item} (by {process_name})")

        except Exception:
            # If parsing fails, capture raw event
            event = {
                "tool": "BLOCKBLOCK",
                "timestamp": timestamp,
                "event": line.strip()
            }
            process_info["events"].append(event)
            print(f"    → [{timestamp}] BlockBlock Event: {line.strip()}")

    def _process_stream_line(self, tool_name, line, process_info):
        """Process a line from a streaming security tool."""
        if not line.strip():
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            tool_lower = tool_name.lower()
            if tool_lower == "lulu":
                self._process_lulu_stream_line(line, timestamp, process_info)
            elif tool_lower == "ransomwhere":
                self._process_ransomwhere_stream_line(line, timestamp, process_info)
            elif tool_lower == "oversight":
                self._process_oversight_stream_line(line, timestamp, process_info)
            elif tool_lower == "blockblock":
                self._process_blockblock_stream_line(line, timestamp, process_info)

        except Exception as e:
            logger.error(f"Error processing {tool_name} stream line: {e}")

    def _get_ransomwhere_version(self, paths=None):
        """
        Get RansomWhere version from system security tools.

        Args:
            paths: Optional paths dict (for compatibility with SystemChecker in multiple inheritance)

        Returns:
            str or None: Version string or None if not found
        """
        if hasattr(self, 'report_data') and 'system_info' in self.report_data:
            security_tools = self.report_data['system_info'].get('security_tool_versions', {})
            ransomwhere_version = security_tools.get('RansomWhere', '')
            if ransomwhere_version:
                # Extract version number from strings like "1.9.0 (Binary)" or "2.0.1 (Application)"
                import re
                version_match = re.match(r'^(\d+\.\d+(?:\.\d+)?)', ransomwhere_version)
                if version_match:
                    return version_match.group(1)
        return None

    def _parse_ransomwhere_version(self, version_string):
        """
        Parse version string to tuple for comparison.
        Returns tuple like (1, 9, 0) or None if invalid.
        """
        if not version_string:
            return None
        try:
            parts = version_string.split('.')
            return tuple(int(p) for p in parts)
        except (ValueError, AttributeError):
            return None

    def parse_ransomwhere_system_log_events(self, since_minutes=60):
        """
        Parse macOS system log for RansomWhere events (pre-1.9.0 versions).
        Returns a list of event dicts for report_data["security_events"].
        """
        import subprocess

        # Build log show command
        cmd = [
            "log", "show",
            "--predicate", 'process == "RansomWhere"',
            "--style", "syslog",
            "--last", f"{since_minutes}m"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to run log show: {result.stderr}")
                return []
            lines = result.stdout.splitlines()
        except Exception as e:
            logger.error(f"Error running log show: {e}")
            return []

        events = []
        # Regex for actionable RansomWhere events (old version format)
        patterns = [
            r'OBJECTIVE-SEE RANSOMWHERE\?: (.+?) is quickly creating encrypted files',
            r'OBJECTIVE-SEE RANSOMWHERE\?: suspending and alerting user',
            r"OBJECTIVE-SEE RANSOMWHERE\?: user responded with 'resume' \(allow\)",
            r"OBJECTIVE-SEE RANSOMWHERE\?: user responded with 'terminate'"
        ]
        for line in lines:
            # Example: 2025-07-31 12:29:35.406362+0100  localhost RansomWhere[8063]: OBJECTIVE-SEE RANSOMWHERE?: /usr/bin/ditto is quickly creating encrypted files
            if "OBJECTIVE-SEE RANSOMWHERE?:" in line:
                timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\+\d{4})", line)
                timestamp = timestamp_match.group(1) if timestamp_match else ""
                for pat in patterns:
                    m = re.search(pat, line)
                    if m:
                        details = {
                            "raw_message": line,
                            "action": "ransomwhere event detected",
                            "severity": "info",
                            "process_path": "Unknown"
                        }
                        if pat == patterns[0]:
                            details["action"] = "file encryption detected"
                            details["severity"] = "high"
                            details["process_path"] = m.group(1)
                        elif pat == patterns[1]:
                            details["action"] = "suspended and alerting user"
                            details["severity"] = "high"
                        elif pat == patterns[2]:
                            details["action"] = "user allowed process"
                            details["severity"] = "medium"
                        elif pat == patterns[3]:
                            details["action"] = "user terminated process"
                            details["severity"] = "high"
                        events.append({
                            "tool": "ransomwhere",
                            "timestamp": timestamp,
                            "event": {
                                "type": "ransomware_alert",
                                "details": details
                            }
                        })
                        break
        return events

    def _extract_timestamp_from_line(self, line):
        """Extract timestamp from RansomWhere log line.

        Args:
            line: Log line to parse

        Returns:
            str: Extracted timestamp or empty string
        """
        timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\+\d{4})", line)
        return timestamp_match.group(1) if timestamp_match else ""

    def _create_ransomware_event(self, timestamp, event_details):
        """Create a standardized ransomware event dict.

        Args:
            timestamp: Event timestamp
            event_details: Dict containing event details

        Returns:
            dict: Formatted event for report_data
        """
        return {
            "tool": "ransomwhere",
            "timestamp": timestamp,
            "event": {
                "type": "ransomware_alert",
                "details": event_details
            }
        }

    def _parse_ransomware_user_allow(self, line, timestamp, encrypted_files):
        """Parse RansomWhere user allow response.

        Args:
            line: Log line to parse
            timestamp: Event timestamp
            encrypted_files: List of encrypted files

        Returns:
            tuple: (event dict, updated encrypted_files list) or (None, encrypted_files)
        """
        allow_match = re.search(r"user says, 'allow', so allowing (.+)$", line)
        if not allow_match:
            return None, encrypted_files

        process_path = allow_match.group(1)
        event_details = {
            "raw_message": line,
            "action": "user allowed process (encryption detected)",
            "severity": "high",
            "process_path": process_path,
            "user_action": "allow"
        }

        if encrypted_files:
            event_details["encrypted_files"] = encrypted_files[:10]
            event_details["encrypted_files_count"] = len(encrypted_files)
            encrypted_files = []

        event = self._create_ransomware_event(timestamp, event_details)
        logger.info(f"RansomWhere: User allowed process with encryption activity: {process_path}")
        return event, encrypted_files

    def _parse_ransomware_user_block(self, line, timestamp, encrypted_files):
        """Parse RansomWhere user block/terminate response.

        Args:
            line: Log line to parse
            timestamp: Event timestamp
            encrypted_files: List of encrypted files

        Returns:
            tuple: (event dict, updated encrypted_files list) or (None, encrypted_files)
        """
        block_match = re.search(r"user says, '[^']+',.*?(?:blocking|terminating|for) (.+)$", line)
        if not block_match:
            return None, encrypted_files

        process_path = block_match.group(1)
        event_details = {
            "raw_message": line,
            "action": "user blocked/terminated process (encryption detected)",
            "severity": "critical",
            "process_path": process_path,
            "user_action": "block"
        }

        if encrypted_files:
            event_details["encrypted_files"] = encrypted_files[:10]
            event_details["encrypted_files_count"] = len(encrypted_files)
            encrypted_files = []

        event = self._create_ransomware_event(timestamp, event_details)
        logger.info(f"RansomWhere: User blocked/terminated process with encryption activity: {process_path}")
        return event, encrypted_files

    def _parse_ransomware_rule_added(self, line, timestamp):
        """Parse RansomWhere rule addition.

        Args:
            line: Log line to parse
            timestamp: Event timestamp

        Returns:
            dict or None: Event dict or None if no match
        """
        rule_match = re.search(r"adding rule: (.+?) -> (allow|block)", line)
        if not rule_match:
            return None

        process_path = rule_match.group(1)
        rule_action = rule_match.group(2)
        event_details = {
            "raw_message": line,
            "action": f"encryption alert rule added ({rule_action})",
            "severity": "medium",
            "process_path": process_path,
            "rule_action": rule_action
        }

        logger.debug(f"RansomWhere: Rule added for {process_path} -> {rule_action}")
        return self._create_ransomware_event(timestamp, event_details)

    def parse_ransomwhere_stream_events(self, lines):
        """
        Parse RansomWhere unified log stream events (v1.9.0+ versions).
        v2.0+ uses Apple Endpoint Security framework for improved detection and process tracking.
        Processes lines from the streaming log command.
        Returns a list of event dicts for report_data["security_events"].
        """
        events = []
        encrypted_files = []

        for line in lines:
            if not line.strip():
                continue

            timestamp = self._extract_timestamp_from_line(line)

            # Pattern 1: Encrypted file detected (debug logging only)
            if "file is encrypted, added to process" in line:
                count_match = re.search(r"file is encrypted, added to process \(count: (\d+)\)", line)
                file_count = count_match.group(1) if count_match else "unknown"
                logger.debug(f"RansomWhere: Encrypted file detected (total count: {file_count})")

            # Pattern 2: Process suspended (debug logging only)
            elif "suspended:" in line:
                suspend_match = re.search(r"suspended: (.+)$", line)
                if suspend_match:
                    process_name = suspend_match.group(1)
                    logger.debug(f"RansomWhere: Process suspended: {process_name}")

            # Pattern 3: Encrypted files list in alert
            elif "sending alert to user (client):" in line or line.strip().startswith('"/'):
                file_match = re.search(r'"(/[^"]+)"', line)
                if file_match:
                    encrypted_files.append(file_match.group(1))

            # Pattern 4: User response to encryption alert (allow)
            elif self.USER_SAYS_ALLOW in line:
                event, encrypted_files = self._parse_ransomware_user_allow(line, timestamp, encrypted_files)
                if event:
                    events.append(event)

            # Pattern 5: User response to encryption alert (block)
            elif self.USER_SAYS_BLOCK in line or "user says, 'terminate'" in line:
                event, encrypted_files = self._parse_ransomware_user_block(line, timestamp, encrypted_files)
                if event:
                    events.append(event)

            # Pattern 6: Rule added
            elif "adding rule:" in line:
                event = self._parse_ransomware_rule_added(line, timestamp)
                if event:
                    events.append(event)

        return events

    def get_ransomwhere_event_markdown(self) -> str:
        """
        Generate a markdown summary of captured RansomWhere events.
        Returns:
            Markdown formatted summary string
        """
        events = []
        # Gather all RansomWhere events from report_data
        if hasattr(self, 'report_data') and 'security_events' in self.report_data:
            for event in self.report_data['security_events']:
                if event.get('tool', '').lower() == 'ransomwhere':
                    details = event.get('event', {}).get('details', {})
                    timestamp = event.get('timestamp', '')
                    action = details.get('action', 'Unknown')
                    process_path = details.get('process_path', 'Unknown')
                    raw_message = details.get('raw_message', '')
                    events.append(f"- [{timestamp}] {action} | Process: `{process_path}` | Message: {raw_message}")
        if not events:
            return ""
        summary = ["### RansomWhere Events Detected\n"]
        summary.extend(events)
        summary.append("")
        return "\n".join(summary)
    """Handles real-time monitoring of security tools."""

    def start_security_monitoring(self):
        """Start monitoring all security tools"""
        print("\n\nStarting security monitoring...")

        # Verify tools if the method is available (through multiple inheritance)
        if hasattr(self, '_verify_security_tools'):
            tool_status = self._verify_security_tools()
            print("\nSecurity Tools Status:")
            print("---------------------")
            for tool, status in tool_status.items():
                print(f"{tool}: {status}")
            print("---------------------\n")

        for tool_name, tool_config in self.security_tools.items():
            try:
                if tool_config["type"] in ["stream", "both"]:
                    print(f"Starting {tool_name} monitoring...")

                    # Use stream_command if available (for tools with both historical and streaming)
                    # Otherwise use the regular command
                    command = tool_config.get("stream_command", tool_config["command"])

                    # Use non-blocking pipes for continuous monitoring
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        universal_newlines=True
                    )
                    self.monitoring_processes[tool_name] = {
                        "process": process,
                        "events": [],
                        "start_time": datetime.now(),
                        "active": True  # Add flag to track monitoring status
                    }
                    # Start a dedicated reader thread for this tool's stdout
                    self._start_reader_thread(tool_name, self.monitoring_processes[tool_name])
                    print(f"✅ {tool_name} monitoring started")

                    # For tools with "both" type, also collect historical events
                    if tool_config["type"] == "both":
                        if tool_name.lower() == "blockblock" and hasattr(self, 'collect_blockblock_unified_log_events'):
                            print(f"   → Collecting historical {tool_name} events...")
                            self.collect_blockblock_unified_log_events(since=f"{DEFAULT_LOG_LOOKBACK_MINUTES}m")
                        elif tool_name.lower() == "lulu" and hasattr(self, 'collect_lulu_unified_log_events'):
                            print(f"   → Collecting historical {tool_name} events...")
                            self.collect_lulu_unified_log_events(since=f"{DEFAULT_LOG_LOOKBACK_MINUTES}m")
                        elif tool_name.lower() == "xprotect" and hasattr(self, 'collect_xprotect_unified_log_events'):
                            print(f"   → Collecting historical {tool_name} events...")
                            self.collect_xprotect_unified_log_events(since=f"{DEFAULT_LOG_LOOKBACK_MINUTES}m")
            except Exception as e:
                logger.error(f"Error starting {tool_name} monitoring: {e}")
                print(f"❌ Error starting {tool_name} monitoring: {e}")        # Start a monitoring thread
        self._start_continuous_monitoring()
        return True

    def _add_tool_events_to_report(self, tool_name, events):
        """Add tool events to report data with proper formatting.

        Args:
            tool_name: Name of the security tool
            events: List of events to add
        """
        if tool_name == "blockblock":
            # Add BlockBlock events with proper structure for report generation
            for event in events:
                if isinstance(event, dict) and "event" in event:
                    self.report_data["security_events"].append({
                        "tool": event.get("tool", "BLOCKBLOCK"),
                        "timestamp": event["timestamp"],
                        "event": event["event"]
                    })
        else:
            # Handle other tools (RansomWhere, LuLu, OverSight, etc.)
            for event in events:
                self.report_data["security_events"].append(event)

    def _run_virustotal_network_analysis(self):
        """Run VirusTotal analysis on network connections.

        Returns:
            List of VirusTotal scan results
        """
        try:
            print("\n🔍 Analyzing network connections with VirusTotal...")
            vt_scan_results = self.scan_lulu_connections_with_virustotal(self.report_data["security_events"])

            # Add results to security events
            for result in vt_scan_results:
                # Format status message with vendor counts
                scan_results = result.get('scan_results', {})
                malicious = scan_results.get('malicious', 0)
                suspicious = scan_results.get('suspicious', 0)
                total_scanned = scan_results.get('total_scanned', 0)
                status = result.get('status', 'unknown')

                # Create descriptive status message
                if status == 'malicious' and malicious > 0:
                    status_msg = f"flagged as malicious by {malicious}/{total_scanned} vendors"
                elif status == 'suspicious' and suspicious > 0:
                    status_msg = f"flagged as suspicious by {suspicious}/{total_scanned} vendors"
                elif status == 'clean':
                    status_msg = f"clean (0/{total_scanned} vendors flagged)"
                else:
                    status_msg = status

                self.report_data["security_events"].append({
                    "tool": "VirusTotal",
                    "timestamp": datetime.now().strftime('%H:%M:%S'),
                    "event": f"Network scan: {result.get('scanned_url', 'unknown')} - {status_msg}",
                    "details": result
                })

            if vt_scan_results:
                print(f"✅ VirusTotal network analysis completed ({len(vt_scan_results)} results)")
            else:
                print("ℹ️ No network connections found for VirusTotal analysis")

            return vt_scan_results

        except Exception as e:
            logger.error(f"Error during VirusTotal network analysis: {e}")
            return []

    def _run_virustotal_dhs_analysis(self):
        """Run VirusTotal analysis on DHS vulnerable files."""
        if self.dhs_vt_analysis_completed:
            # Already completed, show existing results
            existing_dhs_results = [
                event for event in self.report_data.get("security_events", [])
                if event.get("tool") == "VirusTotal-DHS"
            ]
            if existing_dhs_results:
                print(f"\n🔍 Using existing VirusTotal DHS analysis ({len(existing_dhs_results)} results)")
            return

        try:
            dhs_vt_results = self.scan_dhs_vulnerable_files_with_virustotal()

            if dhs_vt_results:
                print(f"\n🔍 VirusTotal DHS analysis completed ({len(dhs_vt_results)} results)")
                # Add results to security events
                for result in dhs_vt_results:
                    self.report_data["security_events"].append({
                        "tool": "VirusTotal-DHS",
                        "timestamp": datetime.now().strftime('%H:%M:%S'),
                        "event": f"DHS file scan: {result.get('file_path', 'unknown')} - Status: {result.get('status', 'unknown')}",
                        "details": result
                    })

            # Mark as completed
            self.dhs_vt_analysis_completed = True

        except Exception as e:
            logger.error(f"Error during VirusTotal DHS file analysis: {e}")
            self.dhs_vt_analysis_completed = True

    def _drain_stream_remaining_lines(self, tool_name, process_info):
        """Drain any remaining lines from the line queue before termination.

        Args:
            tool_name: Name of the security tool
            process_info: Process information dict containing the subprocess
        """
        try:
            line_queue = process_info.get("line_queue")
            if not line_queue:
                return

            # Read remaining queued lines with a short wait for stragglers
            drained = 0
            while drained < 2000:
                try:
                    line = line_queue.get(timeout=0.2)
                except queue.Empty:
                    break
                if line is None:  # EOF sentinel
                    break
                line = line.strip()
                if line:
                    self._process_stream_line(tool_name, line, process_info)
                    drained += 1

            if drained > 0:
                logger.debug(f"Drained {drained} remaining lines from {tool_name} stream")
        except Exception as e:
            logger.debug(f"Error draining {tool_name} stream: {e}")

    def stop_security_monitoring(self):
        """Stop all security monitoring processes"""

        print("\nStopping security monitoring...")

        # Ensure all monitoring events are captured before stopping
        self.check_monitoring_events()

        # Mark all processes as inactive first so monitoring thread exits cleanly
        for process_info in self.monitoring_processes.values():
            process_info["active"] = False

        # Brief pause for monitoring thread to notice and exit
        time.sleep(0.3)

        # Now drain remaining lines and terminate each process
        for tool_name, process_info in self.monitoring_processes.items():
            try:
                # Drain remaining lines from the queue before terminating
                self._drain_stream_remaining_lines(tool_name, process_info)

                process_info["process"].terminate()
                process_info["end_time"] = datetime.now()
                print(f"✅ {tool_name} monitoring stopped")

                # Add events to report data
                self._add_tool_events_to_report(tool_name, process_info["events"])

            except Exception as e:
                logger.error(f"Error checking {tool_name} events: {e}")

        # Run VirusTotal analyses
        self._run_virustotal_network_analysis()
        self._run_virustotal_dhs_analysis()

    def run_security_scans(self):
        """Run one-time security scans"""
        print("\nRunning security scans")
        print("=" * 60)

        for tool_name, tool_config in self.security_tools.items():
            if tool_config["type"] == "scan":
                try:
                    print(f"\nRunning {tool_name} scan...")
                    if tool_name == "dhs":
                        input("\nPlease run a DHS scan manually and press Enter when complete...")
                        if os.path.exists(tool_config["output_path"]):
                            with open(tool_config["output_path"], 'r') as f:
                                scan_output = f.read()
                            self.report_data["security_events"].append({
                                "tool": tool_name,
                                "event": scan_output,
                                "timestamp": datetime.now().strftime('%H:%M:%S')
                            })
                            print(f"✅ {tool_name} scan results collected")
                        else:
                            print(f"❌ {tool_name} scan results file not found")
                    else:
                        scan_result = subprocess.run(
                            tool_config["command"],
                            capture_output=True,
                            text=True
                        )
                        if scan_result.returncode == 0:
                            self.report_data["security_events"].append({
                                "tool": tool_name,
                                "event": scan_result.stdout,
                                "timestamp": datetime.now().strftime('%H:%M:%S')
                            })
                            print(f"✅ {tool_name} scan completed")
                        else:
                            print(f"❌ {tool_name} scan failed: {scan_result.stderr}")
                except Exception as e:
                    logger.error(f"Error running {tool_name} scan: {e}")
                    print(f"❌ Error running {tool_name} scan: {e}")

    def _check_ransomwhere_events(self, process_info):
        """Check for RansomWhere events.

        Version support:
        - v2.0+: Uses Apple Endpoint Security framework with rules, preferences, and improved process hierarchy
        - v1.9.0+: Streaming method with unified log
        - Pre-v1.9.0: Legacy log parsing method

        Args:
            process_info: Process information dict
        """
        version = self._get_ransomwhere_version()
        version_tuple = self._parse_ransomwhere_version(version)
        use_new_method = version_tuple and version_tuple >= (1, 9, 0)

        if use_new_method:
            # For v1.9.0+ (including v2.0+ with Endpoint Security): Events come from streaming
            logger.debug(f"RansomWhere v{version}: Using streaming method (events captured in real-time)")
        else:
            # For pre-1.9.0: Parse system log for historical events
            logger.debug(f"RansomWhere v{version}: Using legacy log parsing method")
            log_events = self.parse_ransomwhere_system_log_events(since_minutes=60)
            for event in log_events:
                print(f"    → [{event.get('timestamp', '')}] RansomWhere event: {event['event']['details']['action']}")
                process_info["events"].append(event)

    def _extract_value_by_path(self, data, key_path, default):
        """Extract a value from nested dict using key path.

        Args:
            data: Dict to extract from
            key_path: List of keys forming the path
            default: Default value if not found

        Returns:
            Extracted value or default
        """
        value = data
        for key in key_path:
            if not isinstance(value, dict):
                return default
            value = value.get(key, {})
        return value if value != {} else default

    def _events_match(self, event, existing_event, compare_keys):
        """Check if two events match based on compare keys.

        Args:
            event: First event
            existing_event: Second event
            compare_keys: List of tuples (key_path, default_value)

        Returns:
            bool: True if events match
        """
        for key_path, default in compare_keys:
            event_val = self._extract_value_by_path(event, key_path, default)
            existing_val = self._extract_value_by_path(existing_event, key_path, default)
            if event_val != existing_val:
                return False
        return True

    def _is_duplicate_event(self, event, existing_events, compare_keys):
        """Check if event is a duplicate.

        Args:
            event: Event to check
            existing_events: List of existing events
            compare_keys: List of tuples (key_path, default_value) to compare

        Returns:
            bool: True if duplicate found
        """
        for existing_event in existing_events:
            if self._events_match(event, existing_event, compare_keys):
                return True
        return False

    def _check_blockblock_events(self, process_info):
        """Check for BlockBlock events.

        Args:
            process_info: Process information dict
        """
        if getattr(self, "_global_historical_collected", {}).get("blockblock", False):
            return

        # Initialize tracking dict if needed
        if not hasattr(self, "_global_historical_collected"):
            self._global_historical_collected = {}

        historical_events = self._collect_blockblock_historical_events(since_minutes=10)
        compare_keys = [
            (['timestamp'], ''),
            (['event', 'details', 'path'], '')
        ]

        for event in historical_events:
            if not self._is_duplicate_event(event, process_info["events"], compare_keys):
                process_info["events"].append(event)
                path = event.get('event', {}).get('details', {}).get('path', 'Unknown')
                app_name = path if path != 'Unknown' else 'unknown item'
                action = event.get('event', {}).get('details', {}).get('action', 'unknown')
                print(f"    → [{event.get('timestamp', '')}] BlockBlock historical event: {action} - {app_name}")

        self._global_historical_collected["blockblock"] = True

    def _check_lulu_events(self, process_info):
        """Check for LuLu events.

        LuLu v4.2.1+ includes relative rule durations, rule export/import,
        and improved flow management for exited processes.

        Args:
            process_info: Process information dict
        """
        if getattr(self, "_global_historical_collected", {}).get("lulu", False):
            return

        # Initialize tracking dict if needed
        if not hasattr(self, "_global_historical_collected"):
            self._global_historical_collected = {}

        historical_events = self._collect_lulu_historical_events(since_minutes=10)
        compare_keys = [
            (['timestamp'], ''),
            (['event'], '')
        ]

        for event in historical_events:
            if not self._is_duplicate_event(event, process_info["events"], compare_keys):
                process_info["events"].append(event)
                event_text = event.get('event', 'Unknown')[:100]
                print(f"    → [{event.get('timestamp', '')}] LuLu historical event: {event_text}...")

        self._global_historical_collected["lulu"] = True

    def check_monitoring_events(self):
        """Check for new events from monitoring processes"""
        for tool_name, process_info in self.monitoring_processes.items():
            try:
                if tool_name == "ransomwhere":
                    self._check_ransomwhere_events(process_info)
                elif tool_name == "blockblock":
                    self._check_blockblock_events(process_info)
                elif tool_name == "lulu":
                    self._check_lulu_events(process_info)
                else:
                    # For other tools, events accumulate in buffers
                    # and are transferred to report_data during stop_security_monitoring()
                    pass
            except Exception as e:
                logger.error(f"Error checking {tool_name} events: {e}")

    def _collect_blockblock_historical_events(self, since_minutes=10):
        """
        Collect BlockBlock events from system log that may have been missed by streaming.
        Returns a list of event dicts in the same format as streaming events.
        """
        cmd = [
            "log", "show",
            "--last", f"{since_minutes}m",
            "--predicate", 'process == "BlockBlock"',
            "--style", "syslog"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"Failed to run log show for BlockBlock: {result.stderr}")
                return []
            lines = result.stdout.splitlines()
        except Exception as e:
            logger.error(f"Error running log show for BlockBlock: {e}")
            return []

        events = []
        for line in lines:
            if self.USER_SAYS in line:
                try:
                    # Extract timestamp from log line (format: 2025-08-01 16:14:54.097367+0100)
                    timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                    if timestamp_match:
                        timestamp = timestamp_match.group(1)
                    else:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Parse the event similar to streaming logic
                    event_data = {
                        "tool": "BLOCKBLOCK",
                        "timestamp": timestamp,
                        "event": {
                            "details": {
                                "action": "user_decision",
                                "timestamp": timestamp,
                                "process_path": "Unknown",
                                "path": "Unknown",
                                "raw_message": line.strip()
                            }
                        }
                    }

                    # Determine if it was allow or block
                    if self.USER_SAYS_ALLOW in line:
                        event_data["event"]["details"]["action"] = "user_allowed"
                    elif self.USER_SAYS_BLOCK in line:
                        event_data["event"]["details"]["action"] = "user_blocked"

                    # Try to extract item binary information (the app being handled)
                    item_match = re.search(r'item binary=name=([^,]+)', line)
                    if item_match:
                        event_data["event"]["details"]["path"] = item_match.group(1)

                    # Try to extract process information - handle multiple patterns
                    name_match = re.search(r'"name":"([^"]+)"', line)
                    path_match = re.search(r'"path":"([^"]+)"', line)
                    if name_match:
                        event_data["event"]["details"]["process_name"] = name_match.group(1)
                    if path_match:
                        event_data["event"]["details"]["process_path"] = path_match.group(1)

                    events.append(event_data)

                except Exception as e:
                    logger.error(f"Error parsing BlockBlock historical event: {e}")
                    # Still capture the raw event
                    events.append({
                        "tool": "BLOCKBLOCK",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": line.strip()
                    })

        return events

    def _collect_lulu_historical_events(self, since_minutes=10):
        """
        Collect LuLu events from system log that may have been missed by streaming.
        Returns a list of event dicts in the same format as streaming events.

        LuLu v4.2.1+ Features:
        - Relative rule durations (not fixed end times)
        - Rule export/import capabilities
        - Flows for exited processes denied by default
        - Enhanced UI improvements

        Event log format compatible across all versions.
        """
        cmd = [
            "log", "show",
            "--last", f"{since_minutes}m",
            "--predicate", 'subsystem == "com.objective-see.lulu"',
            "--style", "syslog"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"Failed to run log show for LuLu: {result.stderr}")
                return []
            lines = result.stdout.splitlines()
        except Exception as e:
            logger.error(f"Error running log show for LuLu: {e}")
            return []

        events = []
        for line in lines:
            if "(user) response:" in line:
                try:
                    # Extract timestamp from log line (format: 2025-08-01 16:14:49.456952+0100)
                    timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                    if timestamp_match:
                        timestamp = timestamp_match.group(1)
                    else:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Create the event in the same format as streaming events
                    event_data = {
                        "tool": "LULU",
                        "timestamp": timestamp,
                        "event": line.strip()
                    }

                    events.append(event_data)

                except Exception as e:
                    logger.error(f"Error parsing LuLu historical event: {e}")
                    # Still capture the raw event
                    events.append({
                        "tool": "LULU",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "event": line.strip()
                    })

        return events

    def _extract_dhs_vulnerable_files(self):
        """Extract vulnerable file paths from DHS events.

        Returns:
            List of unique, existing file paths
        """
        vulnerable_files = []

        for event in self.report_data.get("security_events", []):
            if event.get("tool") != "dhs":
                continue

            try:
                import json
                dhs_output = event.get('event', '')
                if not dhs_output:
                    continue

                dhs_data = json.loads(dhs_output)

                # Extract file paths from hijacked and vulnerable applications
                for app in dhs_data.get("hijacked applications", []):
                    if self.BINARY_PATH_KEY in app:
                        vulnerable_files.append(app[self.BINARY_PATH_KEY])

                for app in dhs_data.get("vulnerable applications", []):
                    if self.BINARY_PATH_KEY in app:
                        vulnerable_files.append(app[self.BINARY_PATH_KEY])

            except (json.JSONDecodeError, KeyError) as e:
                logger.debug(f"Could not parse DHS output as JSON: {e}")
                continue

        # Remove duplicates and filter existing files
        unique_files = []
        for file_path in set(vulnerable_files):
            if os.path.exists(file_path):
                unique_files.append(file_path)
            else:
                logger.warning(f"DHS vulnerable file not found: {file_path}")

        return unique_files

    def _print_vt_scan_result(self, file_path, result):
        """Print VirusTotal scan result summary.

        Args:
            file_path: Path to scanned file
            result: VirusTotal analysis result
        """
        basename = os.path.basename(file_path)
        status = result.get('status', 'unknown')

        if status == 'clean':
            detections = result.get("scan_results", {}).get("detection_ratio", "0/0")
            print(f"   ✅ {basename}: Clean ({detections} detections)")
        elif status == 'malicious':
            detections = result.get("scan_results", {}).get("detection_ratio", "unknown")
            print(f"   ⚠️  {basename}: MALICIOUS ({detections} detections)")
        elif status == 'suspicious':
            detections = result.get("scan_results", {}).get("detection_ratio", "unknown")
            print(f"   ⚠️  {basename}: SUSPICIOUS ({detections} detections)")
        else:
            print(f"   ℹ️  {basename}: {status}")

    def _scan_file_with_virustotal(self, vt_analyzer, file_path):
        """Scan a single file with VirusTotal.

        Args:
            vt_analyzer: VirusTotalAnalyzer instance
            file_path: Path to file to scan

        Returns:
            dict: Analysis result
        """
        try:
            print(f"   🔍 Analyzing {os.path.basename(file_path)} for malware...")
            result = vt_analyzer.analyze_file(file_path)
            if result:
                result['file_path'] = file_path
                self._print_vt_scan_result(file_path, result)
                return result
            return None

        except Exception as e:
            logger.error(f"Error analyzing {file_path} with VirusTotal: {e}")
            return {
                'file_path': file_path,
                'status': 'error',
                'error': str(e)
            }

    def scan_dhs_vulnerable_files_with_virustotal(self):
        """
        Scan DHS vulnerable files with VirusTotal.

        Returns:
            List of VirusTotal scan results for DHS vulnerable files
        """
        unique_files = self._extract_dhs_vulnerable_files()

        if not unique_files:
            logger.info("No DHS vulnerable files found for VirusTotal analysis")
            return []

        print(f"\n🔍 Scanning {len(unique_files)} DHS vulnerable file(s) with VirusTotal...")

        from .virustotal_analyzer import VirusTotalAnalyzer
        vt_analyzer = VirusTotalAnalyzer()

        results = []
        for file_path in unique_files:
            result = self._scan_file_with_virustotal(vt_analyzer, file_path)
            if result:
                results.append(result)

        return results
